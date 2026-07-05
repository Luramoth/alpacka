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
}