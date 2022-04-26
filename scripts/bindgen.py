import subprocess

options = ["--allowlist-function", "PQCLEAN_.*", "--allowlist-var", "PQCLEAN_.*"]

for level in ["2", "3", "5"]:
    for impl in ["clean", "avx2", "aarch64"]:
        cmd = ["bindgen", f"extern/dilithium{level}/{impl}/api.h", "-o", f"src/ffi/dilithium{level}_{impl}.rs"]
        cmd.extend(options)
        print(" ".join(cmd))
        subprocess.run(cmd)
