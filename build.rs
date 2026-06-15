fn main() {
    // Advertise the versioned soname on the shared object.
    //
    // Symbol-export *visibility* is already handled by rustc's own cdylib
    // version script, which exports only our `#[no_mangle]` pub `peios_*`
    // functions and hides everything else. Explicit symbol versioning (named
    // version nodes) can be layered in later if we want a stable versioned ABI;
    // a second anonymous version script can't be combined with rustc's.
    println!("cargo:rustc-cdylib-link-arg=-Wl,-soname,libpeios.so.0");
    println!("cargo:rerun-if-changed=build.rs");
}
