/// Expands in the calling crate, which therefore needs `rust-embed`.
#[macro_export]
macro_rules! catalogue {
    () => {
        #[derive(rust_embed::RustEmbed)]
        #[folder = "i18n"]
        struct Assets;
    };
}
