//! Parameters for dilithium 5.

pub const N: usize = 256;
pub const Q: usize = 8380417;

pub const K: usize = 4;
pub const L: usize = 4;
pub const BETA: usize = 78;
pub const GAMMA1: usize = 1 << 17;
pub const GAMMA2: usize = (Q - 1) / 88;
pub const OMEGA: usize = 80;

pub const POLYW1_PACKEDBYTES: usize = 192;
