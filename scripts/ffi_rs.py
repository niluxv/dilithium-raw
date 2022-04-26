def cfg_all(cfgs: list[str]) -> str:
    if len(cfgs) == 1:
        return "cfg({})".format(cfgs[0])
    else:
        return "cfg(all({}))".format(", ".join(cfgs))

for impl in ["clean", "avx2", "aarch"]:
    for level in [2, 3, 5]:
        cfgs = [f"feature = \"dilithium{level}\""]
        if impl == "avx2":
            cfgs.append("target_arch = \"x86_64\"")
            cfgs.append("target_feature = \"avx2\"")
        elif impl == "aarch":
            # all aarch64 targets have NEON support
            cfgs.append("target_arch = \"aarch64\"")
        print(f"#[{cfg_all(cfgs)}]")
        print(f"pub mod dilithium{level}_{impl};")
