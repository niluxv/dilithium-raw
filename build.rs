macro_rules! build_dilithium_clean {
    ($level:literal, $feature:expr) => {
        if $feature {
            let files_glob = glob::glob(format!("extern/dilithium{}/clean/*.c", $level).as_ref())
                .expect("glob error")
                .map(|g| g.expect("glob error"));

            cc::Build::new()
                .include("extern/common")
                .files(files_glob)
                .compile(format!("dilithium{}_clean", $level).as_ref());
        }
    };
}

macro_rules! build_dilithium_avx2 {
    ($level:literal, $feature:expr) => {
        if $feature {
            let files_glob = glob::glob(format!("extern/dilithium{}/avx2/*.[cS]", $level).as_ref())
                .expect("glob error")
                .map(|g| g.expect("glob error"));

            let mut build = cc::Build::new();
            build
                .include("extern/common")
                .include(format!("extern/dilithium{}/avx2", $level))
                .files(files_glob)
                .flag("-mavx2")
                .compile(format!("dilithium{}_avx2", $level).as_ref());
        }
    };
}

macro_rules! build_dilithium_aarch64 {
    ($level:literal, $feature:expr) => {
        if $feature {
            let files_glob =
                glob::glob(format!("extern/dilithium{}/aarch64/*.[cS]", $level).as_ref())
                    .expect("glob error")
                    .map(|g| g.expect("glob error"));

            cc::Build::new()
                .include("extern/common")
                .files(files_glob)
                .compile(format!("dilithium{}_aarch64", $level).as_ref());
        }
    };
}

fn main() {
    use std::env;

    println!("cargo:rerun-if-changed=extern");

    let feat_dilithium2 = env::var("CARGO_FEATURE_DILITHIUM2").is_ok();
    let feat_dilithium3 = env::var("CARGO_FEATURE_DILITHIUM3").is_ok();
    let feat_dilithium5 = env::var("CARGO_FEATURE_DILITHIUM5").is_ok();
    let feat_avx2 = env::var("CARGO_FEATURE_AVX2").is_ok();
    let feat_aarch64 = env::var("CARGO_FEATURE_AARCH64").is_ok();

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let target_features: std::collections::HashSet<String> = env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap()
        .split(',')
        .map(|s| s.to_string())
        .collect();
    let target_pointer_width = env::var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap();
    let usize_width_bytes = match target_pointer_width.as_ref() {
        "64" => "8",
        "32" => "4",
        _ => panic!("unsupported pointer width"),
    };

    let msvc = target_env == "msvc";
    // asm .S files use system V ABI calling convention and don't support MSVC, so
    // we disable avx2 completely on msvc targets
    let enable_avx2 = target_arch == "x86_64" && feat_avx2 && !msvc;
    // neon is supported on all aarch64 CPUs so no need for dynamic cpu feature
    // detection
    let enable_aarch64 = target_arch == "aarch64" && feat_aarch64 && !msvc;

    // sanity check the C compiler
    cc::Build::new()
        .file("extern/sanity_check.c")
        .define("RUST_USIZE_WIDTH_BYTES", Some(usize_width_bytes))
        .try_compile("sanity_check_build")
        .expect("sanity check build failed");

    let files_glob = glob::glob("extern/common/*.c")
        .expect("glob error")
        .map(|g| g.expect("glob error"));
    cc::Build::new()
        .files(files_glob)
        .compile("pqclean_common_helpers");

    build_dilithium_clean!(2, feat_dilithium2);
    build_dilithium_clean!(3, feat_dilithium3);
    build_dilithium_clean!(5, feat_dilithium5);

    if enable_avx2 {
        println!("cargo:rustc-cfg=enable_avx2");
        build_dilithium_avx2!(2, feat_dilithium2);
        build_dilithium_avx2!(3, feat_dilithium3);
        build_dilithium_avx2!(5, feat_dilithium5);
    } else if enable_aarch64 {
        println!("cargo:rustc-cfg=enable_aarch64");
        build_dilithium_aarch64!(2, feat_dilithium2);
        build_dilithium_aarch64!(3, feat_dilithium3);
        build_dilithium_aarch64!(5, feat_dilithium5);
    }
}
