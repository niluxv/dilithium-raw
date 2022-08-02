#!/usr/bin/env just --justfile

bench-clean:
    cargo criterion --no-default-features --features dilithium5,serde

generate-readme:
    cargo doc2readme
