def cfg_all(cfgs: list[str]) -> str:
    if len(cfgs) == 1:
        return "cfg({})".format(cfgs[0])
    else:
        return "cfg(all({}))".format(", ".join(cfgs))

for impl in ["clean", "avx2", "aarch64"]:
    for level in [2, 3, 5]:
        cfgs = [f"feature = \"dilithium{level}\""]
        if impl == "avx2":
            cfgs.append("enable_avx2")
        elif impl == "aarch64":
            cfgs.append("enable_aarch64")
        print(f"#[{cfg_all(cfgs)}]")
        print(f"pub mod dilithium{level}_{impl};")
