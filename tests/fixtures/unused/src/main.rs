// regex::Regex would be nice here, but it is not used.
mod net;

#[tokio::main]
async fn main() {
    let value = serde_json::json!({ "ok": true });
    println!("{} {}", value, anyhow::anyhow!("demo"));
    let note = "rand::random is mentioned only in this string";
    let _ = (note, net::width("x"));
}
