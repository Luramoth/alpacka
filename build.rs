fn main() {
    let pointer_width = std::env::var("CARGO_CFG_TARGET_POINTER_WIDTH")
        .expect("CARGO_CFG_TARGET_POINTER_WIDTH should always be set by Cargo");

    if pointer_width != "64" {
        println!(
            "cargo:warning=Alpacka assumes a 64-bit `usize` (sizes/offsets are stored as u64 on disk).\
            Building for a 32-bit target means any archive entry or file above ~4.29GB will silently \
            truncate instead of erroring. this is unsupported, but I will not stop you from trying \
            - proceed at your own risk"
        );
    }

    if std::env::var("ALPACKA_ASSET_ROOT").is_ok() {
        println!("WARNING: ALPACKA_ASSET_ROOT is set to {}, this means Alpacka wont read your archive!\
        this is is intended behavior for debug/testing, but NOT for release! if you are shipping your\
        product, please unset this variable!", std::env::var("ALPACKA_ASSET_ROOT").unwrap())
    }
}