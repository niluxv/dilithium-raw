fn main() {
    println!("cargo:rerun-if-changed=extern");

    let feat_dilithium5 = std::env::var("CARGO_FEATURE_DILITHIUM5").is_ok();

    let files_glob = glob::glob("extern/common/*.c").expect("glob error").map(|g| g.expect("glob error"));
    cc::Build::new()
        .files(files_glob)
        .compile("pqclean_common_helpers");

    if feat_dilithium5 {
        let files_glob = glob::glob("extern/dilithium5/clean/*.c").expect("glob error").map(|g| g.expect("glob error"));

        cc::Build::new()
            .include("extern/common")
            .files(files_glob)
            .compile("dilithium5_clean");
    }
}
