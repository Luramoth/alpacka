fn main() {
    if std::env::var("ALPACKA_ASSET_ROOT").is_ok() {
        println!(
            "WARNING: ALPACKA_ASSET_ROOT is set to {}, this means Alpacka wont read your archive!\
        this is is intended behavior for debug/testing, but NOT for release! if you are shipping your\
        product, please unset this variable!",
            std::env::var("ALPACKA_ASSET_ROOT").unwrap()
        )
    }
}
