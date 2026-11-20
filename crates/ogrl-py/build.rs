fn main() {
    pyo3_build_config::add_extension_module_link_args();
    #[cfg(target_os = "macos")]
    {
        // Work around macOS 27 dyld rejecting default rustc min-version LINKEDIT alignment.
        println!("cargo:rustc-cdylib-link-arg=-Wl,-macos_version_min,15.0");
    }
}
