use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Tell Cargo when to re-run this build script
    println!("cargo:rerun-if-changed=native/src/scanner.zig");
    println!("cargo:rerun-if-changed=native/build.zig");
    println!("cargo:rerun-if-changed=assets/gojosix-eye-net.svg");

    // 1. Run `zig build` in the `native` directory
    let status = Command::new("zig")
        .current_dir("native")
        .args(&["build", "-Doptimize=ReleaseSafe"])
        .status()
        .expect("Failed to execute zig build. Is zig installed?");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_path = PathBuf::from(manifest_dir).join("native/zig-out/lib");
    let lib_file = lib_path.join("libwifi_scan.so");

    if !status.success() {
        // Fall back to a prebuilt library if zig build fails but a .so exists.
        if !lib_file.exists() {
            panic!("zig build failed with status {:?} and no prebuilt libwifi_scan.so was found", status);
        }
        println!("cargo:warning=zig build failed; using prebuilt libwifi_scan.so");
    }

    // 2. Tell Cargo where to find the compiled .so library
    println!("cargo:rustc-link-search=native={}", lib_path.display());

    // 3. Link against the library
    println!("cargo:rustc-link-lib=dylib=wifi_scan");

    // 4. Set rpath so the binary can find the .so at runtime without LD_LIBRARY_PATH
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_path.display());
}
