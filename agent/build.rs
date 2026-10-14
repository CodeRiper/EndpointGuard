fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("PROTOC").is_err() {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")?;
        let local_protoc = std::path::Path::new(&manifest_dir).join("../tools/protoc/bin/protoc.exe");
        if local_protoc.exists() {
            std::env::set_var("PROTOC", local_protoc);
        }
    }
    tonic_build::configure()
        .build_server(false) // the agent is only ever a gRPC client
        .compile(&["../proto/telemetry.proto"], &["../proto"])?;
    Ok(())
}
