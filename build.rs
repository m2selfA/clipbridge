fn main() {
    println!("cargo:rerun-if-changed=assets/clipbridge.rc");
    println!("cargo:rerun-if-changed=assets/clipbridge.ico");

    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            if let Err(error) =
                embed_resource::compile("assets/clipbridge.rc", embed_resource::NONE)
                    .manifest_optional()
            {
                println!("cargo:warning=program icon embedding skipped: {error:?}");
            }
        }
    }
}
