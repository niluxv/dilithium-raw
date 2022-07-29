//! Parameters for dilithium 5.

pub const N: usize = 256;
pub const Q: usize = 8380417;

pub const K: usize = 8;
pub const L: usize = 7;
pub const BETA: usize = 120;
pub const GAMMA1: usize = 1 << 19;
pub const GAMMA2: usize = (Q - 1) / 32;
pub const OMEGA: usize = 75;

pub const POLYW1_PACKEDBYTES: usize = 128;
