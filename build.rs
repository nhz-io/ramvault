fn main() {
    // macFUSE's libfuse3 (FSKit backend support lives there, not in a /dev/macfuse fd).
    let fuse = pkg_config::Config::new()
        .atleast_version("3.12")
        .probe("fuse3")
        .expect("libfuse3 not found: install macFUSE (brew install --cask macfuse) and pkgconf");
    let mut cc = cc::Build::new();
    cc.file("src/shim.c").warnings(true).extra_warnings(true);
    for p in &fuse.include_paths {
        cc.include(p);
    }
    cc.compile("rvshim");
    println!("cargo:rerun-if-changed=src/shim.c");
}
