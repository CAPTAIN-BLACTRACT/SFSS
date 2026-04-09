fn main() {
    println!("cargo:rerun-if-changed=proto/vault.proto");
    
    // Create src/proto directory if it doesn't exist
    std::fs::create_dir_all("src/proto").unwrap();

    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    let mut config = prost_build::Config::new();
    // Default output dir is OUT_DIR, but we can instruct prost to put it into src/proto 
    // so we can include it nicely or just use the standard OUT_DIR pattern.
    // Standard pattern is better:
    
    config.compile_protos(&["proto/vault.proto"], &["proto/"]).unwrap();
}
