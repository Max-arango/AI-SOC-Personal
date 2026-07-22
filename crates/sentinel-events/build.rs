use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("proto");

    // Reproducible builds: use a vendored protoc so contributors do not need a
    // system-wide protobuf-compiler installation.
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path()?);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &[
                "sentinel/events/v1/event.proto",
                "sentinel/api/v1/sentinel.proto",
                "sentinel/plugin/v1/plugin.proto",
            ],
            &[proto_root.as_path()],
        )?;

    for p in [
        "sentinel/events/v1/event.proto",
        "sentinel/api/v1/sentinel.proto",
        "sentinel/plugin/v1/plugin.proto",
    ] {
        println!("cargo:rerun-if-changed={}", proto_root.join(p).display());
    }

    Ok(())
}
