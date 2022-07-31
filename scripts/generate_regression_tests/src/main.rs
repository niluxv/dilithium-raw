use clap::Parser;

/// Clap CLI.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
   /// Append mode
   #[clap(short, long, value_parser, default_value_t = true)]
   append: bool,

   /// Number of tests to generate
   #[clap(short, long, value_parser, default_value_t = 1)]
   number: u8,
}

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

        fn generate_test_instance() -> RegressionTestExample {
            use dilithium_raw::util::ByteArray;
            use rand::Rng;

            let mut random = [0; 128];
            let mut rng = rand::rngs::OsRng::default();
            rng.fill(&mut random[..]);
            let seed = ByteArray(random);
            let (pubkey, seckey) = generate_keypair(&mut random);
            // check seed is not changed
            assert_eq!(seed.0, random);
            let message = "hello world".to_string();
            let signature = sign(&message, &seckey);

            RegressionTestExample {
                seed,
                pubkey,
                seckey,
                message,
                signature,
            }
        }

        fn sanity_test(instance: &RegressionTestExample) {
            // Verify `instance` against the implementation
            let mut seed = instance.seed.clone();
            let (pubkey, seckey) = generate_keypair(&mut seed.0);
            // check seed is not changed
            assert_eq!(seed, instance.seed);
            // check key generation determinism
            assert_eq!(pubkey, instance.pubkey);
            assert_eq!(AsRef::<[u8]>::as_ref(&seckey), AsRef::<[u8]>::as_ref(&instance.seckey));
            // check signature determinism
            let signature = sign(&instance.message, &seckey);
            assert_eq!(signature, instance.signature);
            // check verification success
            assert!(verify(&instance.message, &signature, &pubkey).is_ok());
        }

        pub fn generate_tests(args: &crate::Args) {
            use std::fs::File;

            let mut values = if args.append {
                let mut file = File::open($filename).expect("could not open file");
                ron::de::from_reader(&mut file).expect("error during deserialization")
            } else {
                Vec::new()
            };

            values.reserve(args.number.into());
            for _ in 0..args.number {
                values.push(generate_test_instance());
            }
            for value in values.iter() {
                sanity_test(value)
            }
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
    let args = Args::parse();

    dilithium2::generate_tests(&args);
    dilithium3::generate_tests(&args);
    dilithium5::generate_tests(&args);
}
