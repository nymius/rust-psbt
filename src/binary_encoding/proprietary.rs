//! TODO
//!
pub(crate) use encoding::{ByteVecDecoder, BytesEncoder, Decoder, Encoder};
use encoding::{
    ByteVecDecoderError, CompactSizeDecoder, CompactSizeDecoderError, CompactSizeEncoder, Encoder2,
};

use crate::binary_encoding::{PsbtDecodable, PsbtDecoder, PsbtEncodable, PsbtEncoder};
use crate::prelude::Vec;

/// A PSBT key-value pair in its raw byte form.
///
/// - `<keypair> := <key> <value>`
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ProprietaryKey {
    /// Proprietary type prefix used for grouping together keys under some
    /// application and avoid namespace collision
    pub prefix: Vec<u8>,
    /// Custom proprietary subtype
    pub subtype: u64,
    /// Additional key bytes (like serialized public key data etc)
    pub key: Vec<u8>,
}

/// TODO
pub struct PsbtProprietaryKeyEncoder<'a> {
    enc_idx: usize,
    prefix: Encoder2<CompactSizeEncoder, BytesEncoder<'a>>,
    subtype: CompactSizeEncoder,
    key: BytesEncoder<'a>,
}

impl<'a> PsbtEncoder for PsbtProprietaryKeyEncoder<'a> {
    #[inline]
    fn current_chunk(&self) -> &[u8] {
        match self.enc_idx {
            0 => self.prefix.current_chunk(),
            1 => self.subtype.current_chunk(),
            _ => self.key.current_chunk(),
        }
    }

    #[inline]
    fn advance(&mut self) -> bool {
        match self.enc_idx {
            0 => {
                if !self.prefix.advance() {
                    self.enc_idx += 1
                }
                true
            }
            1 => {
                if !self.subtype.advance() {
                    self.enc_idx += 1
                }
                true
            }
            _ => self.key.advance(),
        }
    }
}

impl PsbtEncodable for ProprietaryKey {
    type Encoder<'a>
        = PsbtProprietaryKeyEncoder<'a>
    where
        Self: 'a;

    fn encoder(&self) -> Self::Encoder<'_> {
        PsbtProprietaryKeyEncoder {
            enc_idx: 0,
            prefix: Encoder2::new(
                CompactSizeEncoder::new(self.prefix.len()),
                BytesEncoder::without_length_prefix(&self.prefix),
            ),
            subtype: CompactSizeEncoder::new(self.subtype as usize),
            key: BytesEncoder::without_length_prefix(&self.key),
        }
    }
}

/// TODO
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsbtProprietaryKeyDecoderError {
    /// TODO
    Prefix(ByteVecDecoderError),
    /// TODO
    Subtype(CompactSizeDecoderError),
}

impl alloc::fmt::Display for PsbtProprietaryKeyDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use PsbtProprietaryKeyDecoderError as E;

        match self {
            E::Prefix(ref e) => write!(f, "proprietary key decoder error: {}", e),
            E::Subtype(ref e) => write!(f, "proprietary key decoder error: {}", e),
        }
    }
}

impl PsbtDecodable for ProprietaryKey {
    type Decoder = PsbtProprietaryKeyDecoder;
    fn decoder() -> Self::Decoder { PsbtProprietaryKeyDecoder::new() }
}

/// TODO
pub struct PsbtProprietaryKeyDecoder {
    prefix_decoder: ByteVecDecoder,
    subtype_decoder: CompactSizeDecoder,
    remaining_bytes: Option<Vec<u8>>,
}

impl PsbtProprietaryKeyDecoder {
    /// Constructs a new [`TxOut`] decoder.
    pub const fn new() -> Self {
        Self {
            prefix_decoder: ByteVecDecoder::new(),
            subtype_decoder: CompactSizeDecoder::new(),
            remaining_bytes: None,
        }
    }
}

impl Default for PsbtProprietaryKeyDecoder {
    fn default() -> Self { Self::new() }
}

impl PsbtDecoder for PsbtProprietaryKeyDecoder {
    type Output = ProprietaryKey;
    type Error = PsbtProprietaryKeyDecoderError;

    #[inline]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        let prefix_state = self
            .prefix_decoder
            .push_bytes(bytes)
            .map_err(PsbtProprietaryKeyDecoderError::Prefix)?;

        if prefix_state {
            return Ok(prefix_state);
        }

        let subtype_state = self
            .subtype_decoder
            .push_bytes(bytes)
            .map_err(PsbtProprietaryKeyDecoderError::Subtype)?;

        if subtype_state {
            return Ok(subtype_state);
        }

        self.remaining_bytes = Some((*bytes).to_vec());

        Ok(false)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let prefix = self.prefix_decoder.end().map_err(PsbtProprietaryKeyDecoderError::Prefix)?;
        let subtype_usize =
            self.subtype_decoder.end().map_err(PsbtProprietaryKeyDecoderError::Subtype)?;
        let subtype = u64::try_from(subtype_usize).expect(
            "the maximum encodable value in a compact size unsigned integer fits within u64",
        );

        if let Some(key) = self.remaining_bytes {
            Ok(ProprietaryKey { prefix, subtype, key })
        } else {
            Ok(ProprietaryKey { prefix, subtype, key: vec![] })
        }
    }

    #[inline]
    fn read_limit(&self) -> usize {
        let prefix_limit = self.prefix_decoder.read_limit();

        if prefix_limit > 0 {
            return prefix_limit;
        }

        self.subtype_decoder.read_limit()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProprietaryKey, PsbtDecodable, PsbtDecoder, PsbtEncodable, PsbtEncoder, Vec};

    fn encode_proprietary_key(proprietary_key: ProprietaryKey) -> Vec<u8> {
        let mut proprietary_key_encoder = proprietary_key.encoder();
        let mut advance = true;
        let mut encoded = vec![];

        while advance {
            for &byte in proprietary_key_encoder.current_chunk() {
                encoded.push(byte);
            }
            advance = proprietary_key_encoder.advance();
        }

        encoded
    }

    #[test]
    fn roundtrip() {
        let original = ProprietaryKey {
            prefix: "prefix".as_bytes().to_vec(),
            subtype: 42u64,
            key: "test_key".as_bytes().to_vec(),
        };
        let encoded = encode_proprietary_key(original.clone());
        let mut proprietary_key_decoder = ProprietaryKey::decoder();
        let result = proprietary_key_decoder.push_bytes(&mut encoded.as_slice());

        assert!(!result.unwrap());

        let decoded = proprietary_key_decoder.end().unwrap();

        assert_eq!(original, decoded);
    }

    mod encode {
        use super::*;

        #[test]
        fn no_prefix() {
            let original = ProprietaryKey {
                prefix: vec![],
                subtype: 2u64,
                key: "test_key".as_bytes().to_vec(),
            };
            let encoded = encode_proprietary_key(original);

            assert_eq!(
                &encoded.as_slice(),
                &[0x00, 0x02, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79]
            );
        }

        #[test]
        fn no_key() {
            let original =
                ProprietaryKey { prefix: "prefix".as_bytes().to_vec(), subtype: 2u64, key: vec![] };
            let encoded = encode_proprietary_key(original);

            assert_eq!(&encoded.as_slice(), &[0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02]);
        }

        #[test]
        fn prefix_and_key() {
            let original = ProprietaryKey {
                prefix: "prefix".as_bytes().to_vec(),
                subtype: 2u64,
                key: "test_key".as_bytes().to_vec(),
            };
            let encoded = encode_proprietary_key(original.clone());
            assert_eq!(
                &encoded.as_slice(),
                &[
                    0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02, 0x74, 0x65, 0x73, 0x74, 0x5f,
                    0x6b, 0x65, 0x79
                ]
            );
        }
    }

    mod decode {
        use bitcoin::hex::{test_hex_unwrap as hex, DisplayHex};

        use super::*;

        #[test]
        fn fake_test() {
            let prefix_expected = vec![0x70, 0x72, 0x65, 0x66, 0x69, 0x78];
            let key_expected = vec![0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79];
            assert_eq!(
                prefix_expected,
                hex!(&"prefix".as_bytes().to_hex_string(bitcoin::hex::Case::Lower))
            );
            assert_eq!(
                key_expected,
                hex!(&"test_key".as_bytes().to_hex_string(bitcoin::hex::Case::Lower))
            );
        }

        #[test]
        fn no_prefix() {
            let bytes: Vec<u8> = vec![0x00, 0x02, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79];
            let expected = ProprietaryKey {
                prefix: vec![],
                subtype: 2u64,
                key: "test_key".as_bytes().to_vec(),
            };
            let mut proprietary_key_decoder = ProprietaryKey::decoder();
            let result = proprietary_key_decoder.push_bytes(&mut bytes.as_slice());

            assert!(!result.unwrap());

            let decoded = proprietary_key_decoder.end().unwrap();

            assert_eq!(expected, decoded);
        }

        #[test]
        fn no_key() {
            let bytes: Vec<u8> = vec![0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02];
            let expected =
                ProprietaryKey { prefix: "prefix".as_bytes().to_vec(), subtype: 2u64, key: vec![] };
            let mut proprietary_key_decoder = ProprietaryKey::decoder();
            let result = proprietary_key_decoder.push_bytes(&mut bytes.as_slice());

            assert!(!result.unwrap());

            let decoded = proprietary_key_decoder.end().unwrap();

            assert_eq!(expected, decoded);
        }

        #[test]
        fn prefix_and_key() {
            let bytes: Vec<u8> = vec![
                0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b,
                0x65, 0x79,
            ];
            let expected = ProprietaryKey {
                prefix: "prefix".as_bytes().to_vec(),
                subtype: 2u64,
                key: "test_key".as_bytes().to_vec(),
            };
            let mut proprietary_key_decoder = ProprietaryKey::decoder();
            let result = proprietary_key_decoder.push_bytes(&mut bytes.as_slice());

            assert!(!result.unwrap());

            let decoded = proprietary_key_decoder.end().unwrap();

            assert_eq!(expected, decoded);
        }

        #[test]
        fn initial_read_limit() {
            let decoder = ProprietaryKey::decoder();
            assert_eq!(decoder.read_limit(), 1);
        }

        #[test]
        fn early_end_while_decoding_keylen() {
            let decoder = ProprietaryKey::decoder();
            let result = decoder.end();

            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert_eq!(err_str, "proprietary key decoder error: byte vec decoder error: not enough bytes for decoder, 1 more bytes required");
        }

        /*

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
        */
    }
}
