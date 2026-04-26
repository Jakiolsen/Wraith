fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use the vendored protoc binary so `protoc` doesn't need to be installed.
    // SAFETY: build scripts are single-threaded.
    unsafe { std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap()) };
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&["../proto/orchestrator.proto"], &["../proto"])?;
    Ok(())
}
