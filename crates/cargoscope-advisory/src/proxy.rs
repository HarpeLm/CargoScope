//! HTTP(S) proxy settings from the environment, for the downloads of
//! `cargoscope update`.
//!
//! `HTTPS_PROXY` (or `https_proxy`) is used for `https://` URLs and
//! `HTTP_PROXY` (or `http_proxy`) for `http://` ones; `ALL_PROXY` is the
//! fallback of both. `NO_PROXY` lists the hosts that bypass the proxy
//! (`*`, `example.com`, `.example.com`, `host:port`); loopback addresses
//! always do. A proxy that cannot be used is an error, never a silent direct
//! connection that a firewall would block anyway or, worse, that would leave
//! the company network unnoticed.

use std::time::Duration;

type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// Host of a URL, lowercased, without user information, port or the brackets
/// of an IPv6 address.
fn host_of(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if let Some(inner) = host_port.strip_prefix('[') {
        return inner.split(']').next().unwrap_or(inner);
    }
    host_port.split(':').next().unwrap_or(host_port)
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.starts_with("127.")
        || host == "::1"
        || host.ends_with(".localhost")
}

/// Whether `NO_PROXY` (`no_proxy` as a fallback) exempts `host`.
fn bypassed(host: &str, env: Env<'_>) -> bool {
    let host = host.to_ascii_lowercase();
    if is_loopback(&host) {
        return true;
    }
    let Some(list) = env("NO_PROXY")
        .filter(|value| !value.trim().is_empty())
        .or_else(|| env("no_proxy"))
    else {
        return false;
    };
    list.split([',', ' '])
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .any(|entry| {
            if entry == "*" {
                return true;
            }
            let entry = entry.to_ascii_lowercase();
            let entry = entry.trim_start_matches("*.").trim_start_matches('.');
            // A port in the entry is ignored: the whole host is exempt.
            let entry = if entry.matches(':').count() == 1 {
                entry.split(':').next().unwrap_or(entry)
            } else {
                entry
            };
            !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}")))
        })
}

fn first_set(env: Env<'_>, names: &[&'static str]) -> Option<(&'static str, String)> {
    names.iter().find_map(|name| {
        env(name)
            .filter(|value| !value.trim().is_empty())
            .map(|value| (*name, value.trim().to_owned()))
    })
}

/// The proxy to use for `url` according to `env`, or `None` for a direct
/// connection.
///
/// # Errors
///
/// Returns a message (naming the variable, never its value, which may hold
/// credentials) when the proxy URL is invalid or not an `http://` proxy.
pub(crate) fn select(url: &str, env: Env<'_>) -> Result<Option<ureq::Proxy>, String> {
    let names: &[&'static str] = if url.starts_with("http://") {
        &["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]
    } else {
        &["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
    };
    let Some((name, value)) = first_set(env, names) else {
        return Ok(None);
    };
    if bypassed(host_of(url), env) {
        return Ok(None);
    }
    if let Some((scheme, _)) = value.split_once("://")
        && !scheme.eq_ignore_ascii_case("http")
    {
        return Err(format!(
            "{name} uses the `{scheme}://` scheme: only http:// proxies are supported"
        ));
    }
    let invalid = || format!("{name} is not a valid proxy URL (expected http://host:port)");
    let authority = value
        .split_once("://")
        .map_or(value.as_str(), |(_, rest)| rest);
    let host = host_of(authority);
    if host.is_empty() || host.contains(char::is_whitespace) {
        return Err(invalid());
    }
    ureq::Proxy::new(&value).map(Some).map_err(|_| invalid())
}

/// An agent for downloads from `url`, going through the proxy the
/// environment asks for.
///
/// # Errors
///
/// Returns a message when the proxy settings are unusable.
pub(crate) fn agent_with_env(
    url: &str,
    timeout: Option<Duration>,
    user_agent: Option<&str>,
    env: Env<'_>,
) -> Result<ureq::Agent, String> {
    let mut builder = ureq::AgentBuilder::new();
    if let Some(timeout) = timeout {
        builder = builder.timeout(timeout);
    }
    if let Some(user_agent) = user_agent {
        builder = builder.user_agent(user_agent);
    }
    if let Some(proxy) = select(url, env)? {
        builder = builder.proxy(proxy);
    }
    Ok(builder.build())
}

/// [`agent_with_env`] with the process environment.
pub(crate) fn agent(
    url: &str,
    timeout: Option<Duration>,
    user_agent: Option<&str>,
) -> Result<ureq::Agent, String> {
    agent_with_env(url, timeout, user_agent, &|name| std::env::var(name).ok())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    use super::{agent_with_env, host_of, select};

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> + use<> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    fn proxy(url: &str) -> Option<ureq::Proxy> {
        Some(ureq::Proxy::new(url).expect("valid proxy"))
    }

    #[test]
    fn finds_the_host_of_a_url() {
        assert_eq!(
            host_of("https://index.crates.io/ca/rg/cargo"),
            "index.crates.io"
        );
        assert_eq!(
            host_of("https://user:pw@Example.com:8443/x?y#z"),
            "Example.com"
        );
        assert_eq!(host_of("http://[::1]:8080/x"), "::1");
        assert_eq!(host_of("example.com"), "example.com");
    }

    #[test]
    fn picks_the_variable_of_the_url_scheme() {
        let vars = env(&[
            ("HTTPS_PROXY", "http://secure.proxy:3128"),
            ("HTTP_PROXY", "http://plain.proxy:3128"),
            ("ALL_PROXY", "http://all.proxy:3128"),
        ]);
        assert_eq!(
            select("https://crates.io/api", &vars).unwrap(),
            proxy("http://secure.proxy:3128")
        );
        assert_eq!(
            select("http://example.test/x", &vars).unwrap(),
            proxy("http://plain.proxy:3128")
        );
        // Lowercase names and the ALL_PROXY fallback.
        assert_eq!(
            select("https://crates.io", &env(&[("https_proxy", "proxy:8080")])).unwrap(),
            proxy("proxy:8080")
        );
        assert_eq!(
            select(
                "https://crates.io",
                &env(&[("ALL_PROXY", "http://all.proxy:1")])
            )
            .unwrap(),
            proxy("http://all.proxy:1")
        );
        // Unset or empty: direct connection.
        assert_eq!(select("https://crates.io", &env(&[])).unwrap(), None);
        assert_eq!(
            select("https://crates.io", &env(&[("HTTPS_PROXY", "  ")])).unwrap(),
            None
        );
    }

    #[test]
    fn no_proxy_lists_the_hosts_that_go_direct() {
        let with = |no_proxy: &str| {
            select(
                "https://index.crates.io/x",
                &env(&[("HTTPS_PROXY", "http://p:1"), ("NO_PROXY", no_proxy)]),
            )
            .unwrap()
        };
        assert_eq!(with(""), proxy("http://p:1"));
        assert_eq!(with("*"), None);
        assert_eq!(with("index.crates.io"), None);
        assert_eq!(with("crates.io"), None, "a domain covers its subdomains");
        assert_eq!(with(".crates.io"), None);
        assert_eq!(with("*.crates.io"), None);
        assert_eq!(
            with("INDEX.CRATES.IO:443"),
            None,
            "case and port are ignored"
        );
        assert_eq!(with("example.com, internal ,crates.io"), None);
        assert_eq!(with("example.com,internal"), proxy("http://p:1"));
        assert_eq!(
            with("notcrates.io"),
            proxy("http://p:1"),
            "no partial label match"
        );
        // Lowercase name, and loopback always direct.
        assert_eq!(
            select(
                "https://crates.io",
                &env(&[("HTTPS_PROXY", "http://p:1"), ("no_proxy", "crates.io")])
            )
            .unwrap(),
            None
        );
        for url in [
            "http://localhost:9/x",
            "http://127.0.0.1:9/x",
            "http://[::1]:9/x",
        ] {
            assert_eq!(
                select(url, &env(&[("HTTP_PROXY", "http://p:1")])).unwrap(),
                None
            );
        }
    }

    #[test]
    fn unusable_proxies_are_errors_that_do_not_leak_credentials() {
        let socks = select(
            "https://crates.io",
            &env(&[("HTTPS_PROXY", "socks5://u:secret@p:1")]),
        );
        let error = socks.unwrap_err();
        assert!(
            error.contains("HTTPS_PROXY") && error.contains("only http://"),
            "{error}"
        );
        assert!(!error.contains("secret"), "{error}");
        for bad in ["http://", "http:///", "http://:3128", "not a proxy"] {
            let invalid = select("https://crates.io", &env(&[("HTTPS_PROXY", bad)]));
            assert!(
                invalid.unwrap_err().contains("not a valid proxy URL"),
                "{bad}"
            );
        }
        // A bypassed host never looks at the proxy value.
        assert_eq!(
            select(
                "http://localhost/x",
                &env(&[("HTTP_PROXY", "socks5://p:1")])
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn requests_go_through_the_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut buffer = [0_u8; 2048];
            let read = stream.read(&mut buffer).expect("read");
            stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .expect("write");
            String::from_utf8_lossy(&buffer[..read]).into_owned()
        });
        let proxy_url = format!("http://127.0.0.1:{port}");
        let vars = env(&[("HTTP_PROXY", proxy_url.as_str())]);
        let agent = agent_with_env(
            "http://advisories.example.test/db.tar.gz",
            Some(Duration::from_secs(5)),
            None,
            &vars,
        )
        .expect("agent");
        let result = agent.get("http://advisories.example.test/db.tar.gz").call();
        assert!(result.is_err());
        let request = server.join().expect("proxy thread");
        assert!(
            request.starts_with("GET http://advisories.example.test/db.tar.gz HTTP/1.1"),
            "{request}"
        );
    }
}
