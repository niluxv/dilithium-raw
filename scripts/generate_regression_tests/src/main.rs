macro_rules! generate_dilithium_regression_tests {
    ($filename:expr) => {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct RegressionTestExample {
            seed: dilithium_raw::util::ByteArray<128>,
            pubkey: PublicKey,
            seckey: SecretKey,
            message: String,
            signature: Signature,
        }

        pub fn generate_tests() {
            use dilithium_raw::util::ByteArray;
            use rand::Rng;
            use std::fs::File;

            let mut random = [0; 128];
            let mut rng = rand::rngs::OsRng::default();
            rng.fill(&mut random[..]);
            let seed = ByteArray(random);
            let (pubkey, seckey) = generate_keypair(&mut random);
            // check seed is not changed
            assert_eq!(seed.0, random);
            let message = "hello world".to_string();
            let signature = sign(&message, &seckey);

            let example = RegressionTestExample {
                seed,
                pubkey,
                seckey,
                message,
                signature,
            };

            let values = vec![example];
            let mut file = File::create($filename).expect("could not open file");
            ron::ser::to_writer_pretty(&mut file, &values, ron::ser::PrettyConfig::default())
                .expect("error during serialization");
        }
    };
}

mod dilithium2 {
    use dilithium_raw::dilithium2::*;
    generate_dilithium_regression_tests!("../../src/regression_tests/dilithium2.ron");
}

mod dilithium3 {
    use dilithium_raw::dilithium3::*;
    generate_dilithium_regression_tests!("../../src/regression_tests/dilithium3.ron");
}

mod dilithium5 {
    use dilithium_raw::dilithium5::*;
    generate_dilithium_regression_tests!("../../src/regression_tests/dilithium5.ron");
}

fn main() {
    dilithium2::generate_tests();
    dilithium3::generate_tests();
    dilithium5::generate_tests();
}
