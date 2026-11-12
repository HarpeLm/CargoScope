use unicode_width::UnicodeWidthStr;

pub fn width(text: &str) -> usize {
    let _: Result<serde_json::Value, _> = json5x::from_str("{}");
    text.width()
}
