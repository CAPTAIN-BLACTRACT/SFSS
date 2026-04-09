fn main() {
    prost_build::compile_protos(&["proto/schema.proto"], &["proto/"])
        .expect("Failed to compile Protobuf schema");
}
