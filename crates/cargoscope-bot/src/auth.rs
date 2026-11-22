//! GitHub App RS256 JWT signing and cached installation token exchange.
//!
//! Uses `ring::signature::RsaKeyPair` directly (zero OpenSSL or extra TLS
//! dependencies) and accepts both PKCS#8 (`BEGIN PRIVATE KEY`) and PKCS#1
//! (`BEGIN RSA PRIVATE KEY`) PEM files downloaded from GitHub App settings.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const USER_AGENT: &str = "cargoscope-bot (+https://github.com/HarpeLm/CargoScope)";
const JWT_EXPIRY_SECS: u64 = 540;
const TOKEN_REFRESH_MARGIN_SECS: u64 = 120;
const FALLBACK_TOKEN_TTL_SECS: u64 = 3_000;

#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at_unix: u64,
}

/// Manages RS256 App JWT creation and short-lived installation access tokens.
#[derive(Clone)]
pub struct GitHubAppAuth {
    app_id: String,
    key_pair: Arc<RsaKeyPair>,
    api_base: String,
    rng: SystemRandom,
    tokens: Arc<Mutex<BTreeMap<u64, CachedToken>>>,
}

impl GitHubAppAuth {
    /// Parses a PEM private key (PKCS#8 or PKCS#1 RSA) for the GitHub App.
    ///
    /// # Errors
    /// Returns an error if the PEM framing, Base64 data, or RSA key material is invalid.
    pub fn from_pem(app_id: &str, pem: &str, api_base: &str) -> Result<Self, String> {
        let pkcs8 = pem_to_pkcs8_der(pem)?;
        let key_pair = RsaKeyPair::from_pkcs8(&pkcs8)
            .map_err(|err| format!("Invalid GitHub App RSA private key: {err}"))?;
        Ok(Self {
            app_id: app_id.trim().to_owned(),
            key_pair: Arc::new(key_pair),
            api_base: api_base.trim_end_matches('/').to_owned(),
            rng: SystemRandom::new(),
            tokens: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Creates a signed RS256 JWT valid for GitHub App endpoints (`/app/...`).
    ///
    /// # Errors
    /// Returns an error if signing fails.
    pub fn create_jwt(&self, now_unix: u64) -> Result<String, String> {
        let header = base64_url_encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let iat = now_unix.saturating_sub(60);
        let exp = now_unix.saturating_add(JWT_EXPIRY_SECS);
        let claims_json = serde_json::json!({
            "iat": iat,
            "exp": exp,
            "iss": self.app_id,
        });
        let claims = base64_url_encode(claims_json.to_string().as_bytes());
        let signing_input = format!("{header}.{claims}");
        let mut sig = vec![0u8; self.key_pair.public().modulus_len()];
        self.key_pair
            .sign(
                &RSA_PKCS1_SHA256,
                &self.rng,
                signing_input.as_bytes(),
                &mut sig,
            )
            .map_err(|_| "Failed to sign GitHub App JWT with RS256.".to_owned())?;
        Ok(format!("{signing_input}.{}", base64_url_encode(&sig)))
    }

    /// Returns an installation token (`ghs_...`), refreshing from GitHub if expired.
    ///
    /// # Errors
    /// Returns an error if GitHub rejects the JWT or returns malformed JSON.
    pub fn installation_token(&self, installation_id: u64) -> Result<String, String> {
        let now = now_unix_secs();
        if let Ok(guard) = self.tokens.lock()
            && let Some(cached) = guard.get(&installation_id)
            && cached.expires_at_unix > now.saturating_add(TOKEN_REFRESH_MARGIN_SECS)
        {
            return Ok(cached.token.clone());
        }

        let jwt = self.create_jwt(now)?;
        let url = format!(
            "{}/app/installations/{installation_id}/access_tokens",
            self.api_base
        );
        let response = ureq::post(&url)
            .timeout(REQUEST_TIMEOUT)
            .set("Accept", "application/vnd.github+json")
            .set("Authorization", &format!("Bearer {jwt}"))
            .set("User-Agent", USER_AGENT)
            .set("X-GitHub-Api-Version", "2022-11-28")
            .call()
            .map_err(|err| {
                format!("Installation token request failed for {installation_id}: {err}")
            })?;

        let body: serde_json::Value = serde_json::from_reader(response.into_reader())
            .map_err(|err| format!("Invalid installation token JSON: {err}"))?;
        let token = body
            .get("token")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "GitHub token response omitted 'token'.".to_owned())?
            .to_owned();
        let expires_at_unix = body
            .get("expires_at")
            .and_then(serde_json::Value::as_str)
            .and_then(parse_rfc3339_unix)
            .unwrap_or_else(|| now.saturating_add(FALLBACK_TOKEN_TTL_SECS));

        if let Ok(mut guard) = self.tokens.lock() {
            guard.insert(
                installation_id,
                CachedToken {
                    token: token.clone(),
                    expires_at_unix,
                },
            );
        }
        Ok(token)
    }
}

/// Returns current Unix timestamp in seconds.
#[must_use]
pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Encodes `input` using standard Base64 (with `=` padding), used for Git HTTP Basic headers.
#[must_use]
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let packed = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((packed >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((packed >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((packed >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(packed & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Encodes `input` using URL-safe Base64 without padding (JWT segments).
#[must_use]
pub fn base64_url_encode(input: &[u8]) -> String {
    base64_encode(input)
        .replace('+', "-")
        .replace('/', "_")
        .trim_end_matches('=')
        .to_owned()
}

/// Decodes PEM into PKCS#8 DER bytes, wrapping PKCS#1 RSA keys automatically.
fn pem_to_pkcs8_der(pem: &str) -> Result<Vec<u8>, String> {
    let trimmed = pem.trim();
    if trimmed.contains("BEGIN RSA PRIVATE KEY") {
        let der = decode_pem_block(trimmed, "RSA PRIVATE KEY")?;
        return Ok(wrap_pkcs1_in_pkcs8(&der));
    }
    if trimmed.contains("BEGIN PRIVATE KEY") {
        return decode_pem_block(trimmed, "PRIVATE KEY");
    }
    Err("Expected PEM containing BEGIN PRIVATE KEY or BEGIN RSA PRIVATE KEY.".to_owned())
}

fn decode_pem_block(pem: &str, label: &str) -> Result<Vec<u8>, String> {
    let start_marker = format!("-----BEGIN {label}-----");
    let end_marker = format!("-----END {label}-----");
    let start = pem
        .find(&start_marker)
        .ok_or_else(|| format!("Missing {start_marker}"))?
        + start_marker.len();
    let end = pem[start..]
        .find(&end_marker)
        .ok_or_else(|| format!("Missing {end_marker}"))?;
    let body: String = pem[start..start + end]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    base64_decode(&body)
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(b: u8) -> Result<u8, String> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("Invalid Base64 byte: 0x{b:02x}")),
        }
    }
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return Err("Base64 length is not a multiple of 4.".to_owned());
    }
    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    for chunk in bytes.as_chunks::<4>().0 {
        let pad = usize::from(chunk[2] == b'=') + usize::from(chunk[3] == b'=');
        let a = u32::from(val(chunk[0])?);
        let b = u32::from(val(chunk[1])?);
        let c = if chunk[2] == b'=' {
            0
        } else {
            u32::from(val(chunk[2])?)
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            u32::from(val(chunk[3])?)
        };
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push(((n >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad == 0 {
            out.push((n & 0xff) as u8);
        }
    }
    Ok(out)
}

/// Wraps PKCS#1 RSAPrivateKey DER inside a PKCS#8 PrivateKeyInfo ASN.1 DER envelope.
#[must_use]
pub fn wrap_pkcs1_in_pkcs8(pkcs1: &[u8]) -> Vec<u8> {
    // Version = 0; AlgorithmIdentifier = rsaEncryption (1.2.840.113549.1.1.1) + NULL.
    const HEADER: &[u8] = &[
        0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00,
    ];
    let mut inner = Vec::with_capacity(HEADER.len() + 4 + pkcs1.len());
    inner.extend_from_slice(HEADER);
    inner.push(0x04); // OCTET STRING
    push_der_len(&mut inner, pkcs1.len());
    inner.extend_from_slice(pkcs1);

    let mut outer = Vec::with_capacity(4 + inner.len());
    outer.push(0x30); // SEQUENCE
    push_der_len(&mut outer, inner.len());
    outer.extend_from_slice(&inner);
    outer
}

fn push_der_len(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len <= 0xff {
        buf.push(0x81);
        buf.push(len as u8);
    } else if len <= 0xffff {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
    } else {
        buf.push(0x83);
        buf.push((len >> 16) as u8);
        buf.push(((len >> 8) & 0xff) as u8);
        buf.push((len & 0xff) as u8);
    }
}

/// Minimal parser for `YYYY-MM-DDTHH:MM:SSZ` timestamps returned by GitHub API.
#[must_use]
pub fn parse_rfc3339_unix(ts: &str) -> Option<u64> {
    let trimmed = ts.trim().trim_end_matches('Z');
    let (date, time) = trimmed.split_once('T')?;
    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: u32 = d.next()?.parse().ok()?;
    let day: u32 = d.next()?.parse().ok()?;
    let time_no_frac = time.split('.').next()?;
    let mut t = time_no_frac.split(':');
    let hour: u64 = t.next()?.parse().ok()?;
    let min: u64 = t.next()?.parse().ok()?;
    let sec: u64 = t.next()?.parse().ok()?;
    let days = days_from_civil(year, month, day)?;
    if days < 0 {
        return None;
    }
    Some((days as u64) * 86_400 + hour * 3_600 + min * 60 + sec)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_url_encode_round_trip() {
        let msg = b"x-access-token:ghs_example_token_123";
        let encoded = base64_encode(msg);
        assert_eq!(base64_decode(&encoded).expect("decode"), msg);
        let jwt_seg = base64_url_encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        assert!(!jwt_seg.contains('='));
        assert!(!jwt_seg.contains('+'));
        assert!(!jwt_seg.contains('/'));
    }

    #[test]
    fn pkcs1_wraps_into_valid_pkcs8_envelope() {
        let fake_pkcs1 = vec![0x30, 0x03, 0x02, 0x01, 0x00];
        let wrapped = wrap_pkcs1_in_pkcs8(&fake_pkcs1);
        assert_eq!(wrapped[0], 0x30);
        // Must end cleanly with OCTET STRING containing fake_pkcs1.
        assert!(wrapped.ends_with(&fake_pkcs1));
    }

    #[test]
    fn parses_github_rfc3339_timestamp() {
        assert_eq!(
            parse_rfc3339_unix("2025-01-15T12:30:45Z"),
            Some(1_736_944_245)
        );
    }
}
