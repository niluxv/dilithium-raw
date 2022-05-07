import json
import re
import subprocess

options = ["--size_t-is-usize", "--allowlist-var", "PQCLEAN_.*"]

def main():
    with open("scripts/dilithium.json", 'r') as json_file:
        spec = json.load(json_file)

    for param_set in spec["parameter_sets"]:
        level = param_set["security_level"]
        publickey_bytes = param_set["publickey_bytes"]
        secretkey_bytes = param_set["secretkey_bytes"]
        signature_bytes = param_set["signature_bytes"]
        for impl in param_set["implementations"]:
            assert impl in ["clean", "avx2", "aarch64"]
            IMPL = impl.upper()
            cmd = ["bindgen", f"extern/dilithium{level}/{impl}/api.h"]
            cmd.extend(options)
            result = subprocess.run(cmd, check = True, text = True, capture_output = True)
            out = result.stdout
            m_publickey = re.search(f"const\s+PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_PUBLICKEYBYTES\s*:\s*u32\s*=\s*([0-9]+)\s*;", out)
            m_secretkey = re.search(f"const\s+PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_SECRETKEYBYTES\s*:\s*u32\s*=\s*([0-9]+)\s*;", out)
            m_signature = re.search(f"const\s+PQCLEAN_DILITHIUM{level}_{IMPL}_CRYPTO_BYTES\s*:\s*u32\s*=\s*([0-9]+)\s*;", out)
            assert int(m_publickey.group(1)) == publickey_bytes
            assert int(m_secretkey.group(1)) == secretkey_bytes
            assert int(m_signature.group(1)) == signature_bytes

if __name__ == "__main__":
    main()
