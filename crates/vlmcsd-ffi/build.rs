fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let config = cbindgen::Config::from_file(format!("{}/cbindgen.toml", crate_dir))
        .unwrap_or_default();

    if let Ok(bindings) = cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        bindings.write_to_file(format!("{}/vlmcsd.h", crate_dir));
    }
}
