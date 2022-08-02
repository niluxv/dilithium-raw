pub(crate) trait DilithiumTypes {
    type Poly;
    type PolyVecK;
    type PolyVecL;
    type UninitPoly;

    type Seed;
}

pub(crate) trait DilithiumBasicParams {
    const N: usize;
    const L: usize;
    const K: usize;
    const Q: i32;

    const SEEDBYTES: usize;
    const CRHBYTES: usize;
}

#[cfg(feature = "dilithium2")]
pub mod dilithium2;
#[cfg(feature = "dilithium3")]
pub mod dilithium3;
#[cfg(feature = "dilithium5")]
pub mod dilithium5;

macro_rules! prepare_dilithium_level {
    () => {
        const SEEDBYTES: usize = 32;
        const CRHBYTES: usize = 64;

        mod params;

        /// Polynomial, represented by it's coefficients.
        ///
        /// Corresponds to the `poly` C type.
        #[derive(Clone)]
        #[repr(C)]
        pub struct Poly {
            coeffs: [i32; params::N],
        }

        /// Array of [`params::K`] polynomials.
        ///
        /// Corresponds to the `polyveck` C type.
        #[derive(Clone)]
        #[repr(C)]
        pub struct PolyVecK {
            vec: [Poly; params::K],
        }

        /// Array of [`params::L`] polynomials.
        ///
        /// Corresponds to the `polyvecl` C type.
        #[derive(Clone)]
        #[repr(C)]
        pub struct PolyVecL {
            vec: [Poly; params::L],
        }
    };
}

macro_rules! create_dilithium_instance {
    ($instance:ident, $attr:meta) => {
        #[$attr]
        pub struct $instance;

        impl DilithiumBasicParams for $instance {
            const CRHBYTES: usize = 64;
            const K: usize = params::K;
            const L: usize = params::L;
            const N: usize = params::N;
            const Q: i32 = params::Q as i32;
            const SEEDBYTES: usize = 32;
        }

        impl DilithiumTypes for $instance {
            type Poly = Poly;
            type PolyVecK = PolyVecK;
            type PolyVecL = PolyVecL;
            type Seed = [u8; Self::SEEDBYTES];
            type UninitPoly = UninitArray<i32, { Self::N }>;
        }
    };
}

macro_rules! impl_basic_functions {
    ($dilithium:ty) => {
        impl $dilithium {
            /// Subtract polynomial `b` from `a` in-place, modifying `a`. No modular
            /// reduction is performed.
            fn reduce32(a: &mut i32) {
                let t = (*a + (1 << 22)) >> 23;
                *a -= t * Self::Q;
            }

            /// Add Q if input coefficient is negative.
            fn caddq(a: &mut i32) {
                *a += (*a >> 31) & Self::Q;
            }
        }

        impl $dilithium {
            /// Add polynomial `b` to `a` in-place, modifying `a`. No modular reduction
            /// is performed.
            pub(crate) fn poly_add_inplace(
                a: &mut <Self as DilithiumTypes>::Poly,
                b: &<Self as DilithiumTypes>::Poly,
            ) {
                for i in 0..Self::N {
                    a.coeffs[i] += b.coeffs[i];
                }
            }

            /// Subtract polynomial `b` from `a` in-place, modifying `a`. No modular
            /// reduction is performed.
            pub(crate) fn poly_sub_inplace(
                a: &mut <Self as DilithiumTypes>::Poly,
                b: &<Self as DilithiumTypes>::Poly,
            ) {
                for i in 0..Self::N {
                    a.coeffs[i] -= b.coeffs[i];
                }
            }

            /// Perform modular reduction on the coefficients of the polynomial `a`.
            ///
            /// Reduces all coefficients of the polynomial `a` to representative in
            /// [-6283009,6283008] in-place.
            pub(crate) fn poly_reduce(a: &mut <Self as DilithiumTypes>::Poly) {
                for i in 0..Self::N {
                    Self::reduce32(&mut a.coeffs[i]);
                }
            }

            /// For all coefficients of the polynomial `a` add Q if coefficient is
            /// negative.
            pub(crate) fn poly_caddq(a: &mut <Self as DilithiumTypes>::Poly) {
                for i in 0..Self::N {
                    Self::caddq(&mut a.coeffs[i]);
                }
            }
        }

        impl $dilithium {
            /// Add polynomial array `w` to `v` in-place, modifying `v`. No modular
            /// reduction is performed.
            pub(crate) fn polyveck_add_inplace(
                a: &mut <Self as DilithiumTypes>::PolyVecK,
                b: &<Self as DilithiumTypes>::PolyVecK,
            ) {
                for i in 0..Self::K {
                    Self::poly_add_inplace(&mut a.vec[i], &b.vec[i]);
                }
            }

            /// Add polynomial array `w` to `v` in-place, modifying `v`. No modular
            /// reduction is performed.
            pub(crate) fn polyvecl_add_inplace(
                a: &mut <Self as DilithiumTypes>::PolyVecL,
                b: &<Self as DilithiumTypes>::PolyVecL,
            ) {
                for i in 0..Self::L {
                    Self::poly_add_inplace(&mut a.vec[i], &b.vec[i]);
                }
            }

            /// Subtract polynomial array `w` from `v` in-place, modifying `v`. No
            /// modular reduction is performed.
            pub(crate) fn polyveck_sub_inplace(
                a: &mut <Self as DilithiumTypes>::PolyVecK,
                b: &<Self as DilithiumTypes>::PolyVecK,
            ) {
                for i in 0..Self::K {
                    Self::poly_sub_inplace(&mut a.vec[i], &b.vec[i]);
                }
            }

            /// Subtract polynomial array `w` from `v` in-place, modifying `v`. No
            /// modular reduction is performed.
            pub(crate) fn polyvecl_sub_inplace(
                a: &mut <Self as DilithiumTypes>::PolyVecL,
                b: &<Self as DilithiumTypes>::PolyVecL,
            ) {
                for i in 0..Self::L {
                    Self::poly_sub_inplace(&mut a.vec[i], &b.vec[i]);
                }
            }

            /// Perform modular reduction on the coefficients of the polynomials in the
            /// array `v`.
            pub(crate) fn polyveck_reduce(v: &mut <Self as DilithiumTypes>::PolyVecK) {
                for i in 0..Self::K {
                    Self::poly_reduce(&mut v.vec[i]);
                }
            }

            /// Perform modular reduction on the coefficients of the polynomials in the
            /// array `v`.
            pub(crate) fn polyvecl_reduce(v: &mut <Self as DilithiumTypes>::PolyVecL) {
                for i in 0..Self::L {
                    Self::poly_reduce(&mut v.vec[i]);
                }
            }

            /// For all coefficients of polynomials in the array add Q if coefficient is
            /// negative.
            pub(crate) fn polyveck_caddq(v: &mut <Self as DilithiumTypes>::PolyVecK) {
                for i in 0..Self::K {
                    Self::poly_caddq(&mut v.vec[i]);
                }
            }

            /// For all coefficients of polynomials in the array add Q if coefficient is
            /// negative.
            pub(crate) fn polyvecl_caddq(v: &mut <Self as DilithiumTypes>::PolyVecL) {
                for i in 0..Self::L {
                    Self::poly_caddq(&mut v.vec[i]);
                }
            }
        }
    };
}

pub(crate) use {create_dilithium_instance, impl_basic_functions, prepare_dilithium_level};

mod sign;
