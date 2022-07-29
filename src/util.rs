// Wrapper around a fixed length array of bytes which implements
// [`serde::Serialize`] and [`serde::Deserialize`] as the *byte array* type in
// the `serde` data model.
#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Copy)]
pub struct ByteArray<const N: usize>(pub [u8; N]);

impl<const N: usize> AsRef<[u8; N]> for ByteArray<N> {
    fn as_ref(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> AsMut<[u8; N]> for ByteArray<N> {
    fn as_mut(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> AsRef<[u8]> for ByteArray<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl<const N: usize> AsMut<[u8]> for ByteArray<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl<const N: usize> From<[u8; N]> for ByteArray<N> {
    fn from(arr: [u8; N]) -> Self {
        Self(arr)
    }
}

impl<const N: usize> ByteArray<N> {
    pub fn new(arr: [u8; N]) -> Self {
        Self(arr)
    }
}

#[cfg(feature = "serde")]
pub mod serde {
    use super::ByteArray;
    use core::fmt;
    use serde::de::{Error, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl<const N: usize> Serialize for ByteArray<N> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_bytes(&self.0[..])
        }
    }

    struct ByteArrayVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ByteArrayVisitor<N> {
        type Value = ByteArray<N>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a byte array of length {}", N)
        }

        fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            if v.len() == N {
                let mut bytes = [0; N];
                bytes[..].copy_from_slice(v);
                Ok(ByteArray(bytes))
            } else {
                Err(E::invalid_length(v.len(), &self))
            }
        }
    }

    impl<'de, const N: usize> Deserialize<'de> for ByteArray<N> {
        fn deserialize<D>(deserializer: D) -> Result<ByteArray<N>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(ByteArrayVisitor)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_test::{assert_de_tokens_error, assert_tokens, Token};

        #[test]
        fn test_bytearray_tokens() {
            let bytes = b"hello";
            let serde_bytearr = ByteArray(*bytes);

            assert_tokens(&serde_bytearr, &[Token::Bytes(bytes.as_ref())]);
        }

        #[test]
        fn test_bytearray_len_error() {
            let bytes = b"hello";

            assert_de_tokens_error::<ByteArray<4>>(
                &[Token::Bytes(bytes.as_ref())],
                "invalid length 5, expected a byte array of length 4",
            );

            assert_de_tokens_error::<ByteArray<6>>(
                &[Token::Bytes(bytes.as_ref())],
                "invalid length 5, expected a byte array of length 6",
            );
        }
    }
}

/// Convert a reference to a slice to a reference to an array of length `N`.
///
/// # Panics
/// Panics when the slice length differs from `N`.
pub(crate) fn slice_as_array<T, const N: usize>(arr: &[T]) -> &[T; N] {
    arr.try_into()
        .expect("slice length differs from expected array length")
}

/// Convert a mutable reference to a slice to a mutable reference to an array of
/// length `N`.
///
/// # Panics
/// Panics when the slice length differs from `N`.
pub(crate) fn slice_as_array_mut<T, const N: usize>(arr: &mut [T]) -> &mut [T; N] {
    arr.try_into()
        .expect("slice length differs from expected array length")
}
