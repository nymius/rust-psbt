//! TODO
//!
pub(crate) use encoding::{ByteVecDecoder, BytesEncoder, Decoder, Encoder};
use encoding::{ByteVecDecoderError, CompactSizeEncoder, Encoder2};

use super::key::{PsbtKeyDecoderError, PsbtKeyEncoder};
use crate::binary_encoding::key::{Key, PsbtKeyDecoder};
use crate::binary_encoding::{PsbtDecodable, PsbtDecoder, PsbtEncodable, PsbtEncoder};
use crate::prelude::Vec;

/// A PSBT key-value pair in its raw byte form.
///
/// - `<keypair> := <key> <value>`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPair {
    /// The key of this key-value pair.
    pub key: Key,
    /// The value of this key-value pair in raw byte form.
    ///
    /// - `<value> := <valuelen> <valuedata>`
    pub value: Vec<u8>,
}

/// TODO
pub struct PsbtKeyPairEncoder<'a> {
    enc_idx: usize,
    key: PsbtKeyEncoder<'a>,
    value: Encoder2<CompactSizeEncoder, BytesEncoder<'a>>,
}

impl<'a> PsbtEncoder for PsbtKeyPairEncoder<'a> {
    #[inline]
    fn current_chunk(&self) -> &[u8] {
        if self.enc_idx == 0 {
            self.key.current_chunk()
        } else {
            self.value.current_chunk()
        }
    }

    #[inline]
    fn advance(&mut self) -> bool {
        if self.enc_idx == 0 {
            if !self.key.advance() {
                self.enc_idx += 1;
            }
            true
        } else {
            self.value.advance()
        }
    }
}

impl PsbtEncodable for KeyPair {
    type Encoder<'a>
        = PsbtKeyPairEncoder<'a>
    where
        Self: 'a;

    fn encoder(&self) -> Self::Encoder<'_> {
        PsbtKeyPairEncoder {
            enc_idx: 0,
            key: self.key.encoder(),
            value: Encoder2::new(
                CompactSizeEncoder::new(self.value.len()),
                BytesEncoder::without_length_prefix(&self.value),
            ),
        }
    }
}

/// TODO
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsbtKeyPairDecoderError {
    /// TODO
    Key(PsbtKeyDecoderError),
    /// TODO
    Value(ByteVecDecoderError),
}

impl alloc::fmt::Display for PsbtKeyPairDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use PsbtKeyPairDecoderError as E;

        match self {
            E::Key(ref e) => write!(f, "keypair decoder error: {}", e),
            E::Value(ref e) => write!(f, "keypair decoder error: {}", e),
        }
    }
}

impl PsbtDecodable for KeyPair {
    type Decoder = PsbtKeyPairDecoder;
    fn decoder() -> Self::Decoder { PsbtKeyPairDecoder::new() }
}

/// TODO
pub struct PsbtKeyPairDecoder {
    key_decoder: PsbtKeyDecoder,
    value_decoder: ByteVecDecoder,
}

impl PsbtKeyPairDecoder {
    /// Constructs a new [`TxOut`] decoder.
    pub const fn new() -> Self {
        Self { key_decoder: PsbtKeyDecoder::new(), value_decoder: ByteVecDecoder::new() }
    }
}

impl Default for PsbtKeyPairDecoder {
    fn default() -> Self { Self::new() }
}

impl PsbtDecoder for PsbtKeyPairDecoder {
    type Output = KeyPair;
    type Error = PsbtKeyPairDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        let key_state = self.key_decoder.push_bytes(bytes).map_err(PsbtKeyPairDecoderError::Key)?;

        if key_state {
            return Ok(key_state);
        }

        let value_state =
            self.value_decoder.push_bytes(bytes).map_err(PsbtKeyPairDecoderError::Value)?;

        Ok(value_state)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let key = self.key_decoder.end().map_err(PsbtKeyPairDecoderError::Key)?;
        let value = self.value_decoder.end().map_err(PsbtKeyPairDecoderError::Value)?;

        Ok(KeyPair { key, value })
    }

    #[inline]
    fn read_limit(&self) -> usize {
        let key_limit = self.key_decoder.read_limit();

        if key_limit > 0 {
            return key_limit;
        }

        self.value_decoder.read_limit()
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyPair, PsbtDecodable, PsbtDecoder, PsbtEncodable, PsbtEncoder, Vec};
    use crate::binary_encoding::key::Key;

    fn encode_keypair(keypair: KeyPair) -> Vec<u8> {
        let mut keypair_encoder = keypair.encoder();
        let mut advance = true;
        let mut encoded = vec![];

        while advance {
            for &byte in keypair_encoder.current_chunk() {
                encoded.push(byte);
            }
            advance = keypair_encoder.advance();
        }

        encoded
    }

    #[test]
    fn roundtrip() {
        let original = KeyPair {
            key: Key { ttype: 0x06, data: vec![0x01, 0x02, 0x03, 0x04] },
            value: vec![0x01, 0x02, 0x03],
        };
        let encoded = encode_keypair(original.clone());
        let mut key_decoder = KeyPair::decoder();
        let result = key_decoder.push_bytes(&mut encoded.as_slice());

        assert!(!result.unwrap());

        let decoded = key_decoder.end().unwrap();

        assert_eq!(original, decoded);
    }

    mod encode {
        use super::*;

        #[test]
        fn key_only() {
            let key =
                KeyPair { key: Key { ttype: 0x02, data: vec![0x01, 0x02, 0x03] }, value: vec![] };
            let encoded = encode_keypair(key);

            assert_eq!(&encoded.as_slice(), &[0x04, 0x02, 0x01, 0x02, 0x03, 0x00]);
        }

        #[test]
        fn keypair_with_value() {
            let key = KeyPair {
                key: Key { ttype: 0x02, data: vec![0x01, 0x02, 0x03] },
                value: vec![0x01, 0x02],
            };
            let encoded = encode_keypair(key);

            assert_eq!(&encoded.as_slice(), &[0x04, 0x02, 0x01, 0x02, 0x03, 0x02, 0x01, 0x02]);
        }
    }

    mod decode {
        use super::*;
        use crate::binary_encoding::pair::PsbtKeyPairDecoder;

        #[test]
        fn keytype_only() {
            let bytes: Vec<u8> = vec![0x04, 0x02, 0x01, 0x02, 0x03, 0x00];
            let mut keypair_decoder = KeyPair::decoder();
            let _ = keypair_decoder.push_bytes(&mut bytes.as_slice());
            let keypair = keypair_decoder.end().unwrap();

            assert_eq!(keypair.key, Key { ttype: 0x02, data: vec![0x01, 0x02, 0x03] });
            assert!(keypair.value.is_empty());
        }

        #[test]
        fn keypair_with_value() {
            let bytes: Vec<u8> = vec![0x04, 0x02, 0x01, 0x02, 0x03, 0x02, 0x01, 0x02];
            let mut keypair_decoder = KeyPair::decoder();
            let _ = keypair_decoder.push_bytes(&mut bytes.as_slice());
            let keypair = keypair_decoder.end().unwrap();
            let expected = KeyPair {
                key: Key { ttype: 0x02, data: vec![0x01, 0x02, 0x03] },
                value: vec![0x01, 0x02],
            };

            assert_eq!(keypair, expected);
        }

        #[test]
        fn initial_read_limit() {
            let decoder = KeyPair::decoder();
            assert_eq!(decoder.read_limit(), 1);
        }

        #[test]
        fn early_end_while_decoding_keylen() {
            let decoder = PsbtKeyPairDecoder::new();
            let result = decoder.end();

            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert_eq!(err_str, "keypair decoder error: early end of key (still decoding length)");
        }

        #[test]
        fn early_end_while_decoding_type() {
            let mut decoder = PsbtKeyPairDecoder::new();
            let mut bytes: &[u8] = &[0x01];
            let _ = decoder.push_bytes(&mut bytes);
            // Provide a partial, larger than 1 byte compact size unsigned integer
            let mut bytes: &[u8] = &[0xfd];
            let needs_more = decoder.push_bytes(&mut bytes).unwrap();
            assert!(needs_more); // needs_more should be true, because 0xfd requires 3 bytes

            let result = decoder.end();
            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert_eq!(err_str, "keypair decoder error: early end of key (still decoding type)");
        }

        #[test]
        fn push_bytes_incremental_push() {
            let mut decoder = PsbtKeyPairDecoder::new();

            let full_bytes = vec![0x04, 0x02, 0x01, 0x02, 0x03, 0x02, 0x01, 0x02];

            for byte in full_bytes {
                let mut slice: &[u8] = &[byte];
                let needs_more = decoder.push_bytes(&mut slice).unwrap();

                assert!(needs_more || slice.is_empty());
            }

            let keypair = decoder.end().unwrap();
            assert_eq!(
                keypair,
                KeyPair {
                    key: Key { ttype: 0x02, data: vec![0x01, 0x02, 0x03] },
                    value: vec![0x01, 0x02]
                }
            );
        }

        #[test]
        fn empty_slice() {
            let mut decoder = PsbtKeyPairDecoder::new();
            let mut empty: &[u8] = &[];

            let result = decoder.push_bytes(&mut empty).unwrap();
            assert!(result);
        }
    }
}
