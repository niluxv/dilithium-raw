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

#[derive(Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Clone, Copy)]
pub struct ByteArrayVec<const N: usize> {
    pub bytes: [u8; N],
    pub len: usize,
}

impl<const N: usize> AsRef<[u8]> for ByteArrayVec<N> {
    fn as_ref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<const N: usize> AsMut<[u8]> for ByteArrayVec<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}

impl<const N: usize> ByteArrayVec<N> {
    pub fn new(bytes: [u8; N], len: usize) -> Self {
        Self { bytes, len }
    }
}

#[cfg(feature = "serde")]
pub mod serde {
    use super::{ByteArray, ByteArrayVec};
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

    impl<const N: usize> Serialize for ByteArrayVec<N> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_bytes(&self.bytes[..self.len])
        }
    }

    struct ByteArrayVecVisitor<const N: usize>;

    impl<'de, const N: usize> Visitor<'de> for ByteArrayVecVisitor<N> {
        type Value = ByteArrayVec<N>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a byte array of length at most {}", N)
        }

        fn visit_bytes<E: Error>(self, v: &[u8]) -> Result<Self::Value, E> {
            let len = v.len();
            if len <= N {
                let mut bytes = [0; N];
                bytes[..len].copy_from_slice(v);
                Ok(ByteArrayVec { bytes, len })
            } else {
                Err(E::invalid_length(len, &self))
            }
        }
    }

    impl<'de, const N: usize> Deserialize<'de> for ByteArrayVec<N> {
        fn deserialize<D>(deserializer: D) -> Result<ByteArrayVec<N>, D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_bytes(ByteArrayVecVisitor)
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

        #[test]
        fn test_bytearrayvec_tokens() {
            let bytes = b"hello\0\0";
            let serde_bytearrvec = ByteArrayVec {
                bytes: *bytes,
                len: 5,
            };

            assert_tokens(&serde_bytearrvec, &[Token::Bytes(b"hello".as_ref())]);
        }

        #[test]
        fn test_bytearrayvec_len_error() {
            let bytes = b"hello";

            assert_de_tokens_error::<ByteArrayVec<4>>(
                &[Token::Bytes(bytes.as_ref())],
                "invalid length 5, expected a byte array of length at most 4",
            );
        }
    }
}
