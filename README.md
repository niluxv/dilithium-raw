# dilithium-raw ![License](https://img.shields.io/crates/l/dilithium-raw) [![dilithium-raw on crates.io](https://img.shields.io/crates/v/dilithium-raw)](https://crates.io/crates/dilithium-raw) [![dilithium-raw on docs.rs](https://docs.rs/dilithium-raw/badge.svg)](https://docs.rs/dilithium-raw)

Low level library for post-quantum signature scheme dilithium.

Uses a slightly modified version of the C code of [`pqclean`][__link0] as the actual implementation, which is compiled by a build script. The API is modified to put the user in control of required randomness.

The library has a minimal set of dependencies: in the default configuration (without [`serde`][__link1] support) only [`cty`][__link2].


## Security

**Warning**: This crate is intended as a lower level crate implementing a primitive and exposing “not hard to misuse” APIs to provide the user with maximum control. Only use if you know what you are doing! Always read security sections in the documentation. Otherwise use a higher level wrapper.

**Warning**: This crate has not been audited for correctness. The C code is copied from the well-regarded [`pqclean`][__link3] project, but since then modifications have been made.

USE AT YOUR OWN RISK!


## Usage

The API is located in the `dilithiumX` module, for X in {2, 3, 5}. To generate a keypair, use `generate_keypair`. Note: it requires a buffer filled with cryptographically secure random bytes. The random buffer is not modified, so zeroization is left to the user. Example:


```rust
use dilithium_raw::dilithium5::generate_keypair;
use rand::rngs::OsRng;
use rand::Rng;
use zeroize::Zeroize;

// fill buffer of 128 bytes with secure random data
let mut random = [0; 128];
OsRng.fill(&mut random[..]);

// generate keypair
let (pubkey, seckey) = generate_keypair(&mut random);

// zeroize the buffer with random data
random.zeroize();
```

To sign a message using the secret key, use `sign` and to verify it using the public key, use `verify`. `verify` returns `Ok` for a valid signature and `Err` for an invalid signature. Example:


```rust
use dilithium_raw::dilithium5::{sign, verify};

// snip, get a `pubkey` and `seckey` with the public and secret key respectively

let msg = "hello world";
let sig = sign(msg, &seckey);
assert!(verify(msg, &sig, &pubkey).is_ok());
```


 [__link0]: https://github.com/PQClean/PQClean
 [__link1]: https://crates.io/crates/serde
 [__link2]: https://crates.io/crates/cty
 [__link3]: https://github.com/PQClean/PQClean
