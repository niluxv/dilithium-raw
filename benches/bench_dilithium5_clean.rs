use criterion::{criterion_group, criterion_main, Criterion};
use dilithium_raw::dilithium5::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct RegressionTestExample {
    seed: dilithium_raw::util::ByteArray<128>,
    pubkey: PublicKey,
    seckey: SecretKey,
    message: String,
    signature: Signature,
}

fn bench_dilithium5_clean_verify(c: &mut Criterion) {
    let ron_str = include_str!("dilithium5.ron");
    let example: RegressionTestExample =
        ron::de::from_str(ron_str).expect("could not deserialize regression test file");
    c.bench_function("Dilithium5 CLEAN verify", |b| {
        b.iter(|| verify(&example.message, &example.signature, &example.pubkey))
    });
}

fn bench_dilithium5_clean_sign(c: &mut Criterion) {
    let ron_str = include_str!("dilithium5.ron");
    let example: RegressionTestExample =
        ron::de::from_str(ron_str).expect("could not deserialize regression test file");
    c.bench_function("Dilithium5 CLEAN sign", |b| {
        b.iter(|| sign(&example.message, &example.seckey))
    });
}

fn bench_dilithium5_clean_keygen(c: &mut Criterion) {
    let ron_str = include_str!("dilithium5.ron");
    let mut example: RegressionTestExample =
        ron::de::from_str(ron_str).expect("could not deserialize regression test file");
    c.bench_function("Dilithium5 CLEAN keygen", |b| {
        b.iter(|| generate_keypair(&mut example.seed.0))
    });
}

criterion_group!(
    bench_dilithium5_clean,
    bench_dilithium5_clean_verify,
    bench_dilithium5_clean_sign,
    bench_dilithium5_clean_keygen
);
criterion_main!(bench_dilithium5_clean);
