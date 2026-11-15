use serde::Serialize;

#[derive(Serialize)]
struct Event {
    at: String,
}

fn main() {
    let event = Event { at: chrono::Utc::now().to_rfc3339() };
    println!("{}", serde_json::to_string(&event).unwrap());
}
