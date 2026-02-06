//! TODO
//!
pub(crate) use encoding::{ByteVecDecoder, BytesEncoder, Decoder, Encoder};
use encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoderError, CompactSizeDecoder, CompactSizeDecoderError, CompactSizeEncoder, Encoder2, UnexpectedEofError
};

use crate::binary_encoding::{PsbtDecodable, PsbtDecoder, PsbtEncodable, PsbtEncoder};
use crate::prelude::Vec;

/// A PSBT key-value pair in its raw byte form.
///
/// - `<keypair> := <key> <value>`
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProprietaryKey<const N: usize> {
    /// Proprietary type prefix used for grouping together keys under some
    /// application and avoid namespace collision
    pub prefix: Vec<u8>,
    /// Custom proprietary subtype
    pub subtype: u64,
    /// Additional key bytes (like serialized public key data etc)
    pub subkeydata: [u8; N],
}

/// TODO
pub struct PsbtProprietaryKeyEncoder<'a, const N: usize> {
    enc_idx: usize,
    prefix: Encoder2<CompactSizeEncoder, BytesEncoder<'a>>,
    subtype: CompactSizeEncoder,
    subkeydata: ArrayEncoder<N>,
}

impl<'a, const N: usize> PsbtEncoder for PsbtProprietaryKeyEncoder<'a, N> {
    #[inline]
    fn current_chunk(&self) -> &[u8] {
        match self.enc_idx {
            0 => self.prefix.current_chunk(),
            1 => self.subtype.current_chunk(),
            _ => self.subkeydata.current_chunk(),
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
            _ => self.subkeydata.advance(),
        }
    }
}

impl<const N: usize> PsbtEncodable for ProprietaryKey<N> {
    type Encoder<'a>
        = PsbtProprietaryKeyEncoder<'a, N>
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
            subkeydata: ArrayEncoder::without_length_prefix(self.subkeydata),
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
    /// TODO
    SubKeyData(UnexpectedEofError),
}

impl alloc::fmt::Display for PsbtProprietaryKeyDecoderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use PsbtProprietaryKeyDecoderError as E;

        match self {
            E::Prefix(ref e) => write!(f, "proprietary key decoder error: {}", e),
            E::Subtype(ref e) => write!(f, "proprietary key decoder error: {}", e),
            E::SubKeyData(ref e) => write!(f, "proprietary key decoder error: {}", e),
        }
    }
}

impl<const N: usize> PsbtDecodable for ProprietaryKey<N> {
    type Decoder = PsbtProprietaryKeyDecoder<N>;
    fn decoder() -> Self::Decoder { PsbtProprietaryKeyDecoder::new() }
}

/// TODO
pub struct PsbtProprietaryKeyDecoder<const N: usize> {
    prefix_decoder: ByteVecDecoder,
    subtype_decoder: CompactSizeDecoder,
    subkeydata_decoder: ArrayDecoder<N>,
}

impl<const N: usize> PsbtProprietaryKeyDecoder<N> {
    /// Constructs a new [`TxOut`] decoder.
    pub const fn new() -> Self {
        Self {
            prefix_decoder: ByteVecDecoder::new(),
            subtype_decoder: CompactSizeDecoder::new(),
            subkeydata_decoder: ArrayDecoder::<N>::new(),
        }
    }
}

impl<const N: usize> Default for PsbtProprietaryKeyDecoder<N> {
    fn default() -> Self { Self::new() }
}

impl<const N: usize> PsbtDecoder for PsbtProprietaryKeyDecoder<N> {
    type Output = ProprietaryKey<N>;
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

        self.subkeydata_decoder.push_bytes(bytes).map_err(PsbtProprietaryKeyDecoderError::SubKeyData)
    }

    #[inline]
    fn end(self) -> Result<Self::Output, Self::Error> {
        let prefix = self.prefix_decoder.end().map_err(PsbtProprietaryKeyDecoderError::Prefix)?;
        let subtype_usize =
            self.subtype_decoder.end().map_err(PsbtProprietaryKeyDecoderError::Subtype)?;
        let subtype = u64::try_from(subtype_usize).expect(
            "the maximum encodable value in a compact size unsigned integer fits within u64",
        );

        let subkeydata = self.subkeydata_decoder.end().map_err(PsbtProprietaryKeyDecoderError::SubKeyData)?;


        Ok(ProprietaryKey { prefix, subtype, subkeydata })
    }

    #[inline]
    fn read_limit(&self) -> usize {
        let prefix_limit = self.prefix_decoder.read_limit();

        if prefix_limit > 0 {
            return prefix_limit;
        }

        let subtype_limit = self.subtype_decoder.read_limit();

        if subtype_limit > 0 {
            return subtype_limit;
        }

        self.subkeydata_decoder.read_limit()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProprietaryKey, PsbtDecodable, PsbtDecoder, PsbtEncodable, PsbtEncoder, Vec};

    // Bytes represent the "test_key" string in utf8
    const TEST_SUBKEYDATA: [u8; 8] = [0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79];

    fn encode_proprietary_key<const N: usize>(proprietary_key: ProprietaryKey<N>) -> Vec<u8> {
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
            subkeydata: TEST_SUBKEYDATA,
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
                subkeydata: TEST_SUBKEYDATA,
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
                ProprietaryKey { prefix: "prefix".as_bytes().to_vec(), subtype: 2u64, subkeydata: [] };
            let encoded = encode_proprietary_key(original);

            assert_eq!(&encoded.as_slice(), &[0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02]);
        }

        #[test]
        fn prefix_and_key() {
            let original = ProprietaryKey {
                prefix: "prefix".as_bytes().to_vec(),
                subtype: 2u64,
                subkeydata: TEST_SUBKEYDATA,
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
        use crate::binary_encoding::proprietary::PsbtProprietaryKeyDecoder;

        use super::*;

        #[test]
        fn no_prefix() {
            let bytes: Vec<u8> = vec![0x00, 0x02, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79];
            let expected = ProprietaryKey {
                prefix: vec![],
                subtype: 2u64,
                subkeydata: TEST_SUBKEYDATA,
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
                ProprietaryKey { prefix: "prefix".as_bytes().to_vec(), subtype: 2u64, subkeydata: [] };
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
                subkeydata: TEST_SUBKEYDATA,
            };
            let mut proprietary_key_decoder = ProprietaryKey::decoder();
            let result = proprietary_key_decoder.push_bytes(&mut bytes.as_slice());

            assert!(!result.unwrap());

            let decoded = proprietary_key_decoder.end().unwrap();

            assert_eq!(expected, decoded);
        }

        #[test]
        fn initial_read_limit() {
            let decoder = ProprietaryKey::<8>::decoder();
            assert_eq!(decoder.read_limit(), 1);
        }

        #[test]
        fn early_end_while_reading_subtype() {
            let decoder = ProprietaryKey::<8>::decoder();
            let result = decoder.end();

            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert_eq!(err_str, "proprietary key decoder error: byte vec decoder error: not enough bytes for decoder, 1 more bytes required");
        }

        #[test]
        fn early_end_while_reading_subkeydata() {
            let bytes: Vec<u8> = vec![
                0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02
            ];

            let mut decoder = ProprietaryKey::<8>::decoder();

            for byte in bytes {
                let mut slice: &[u8] = &[byte];
                let needs_more = decoder.push_bytes(&mut slice).unwrap();

                assert!(needs_more || slice.is_empty());
            }

            let result = decoder.end();

            assert!(result.is_err());
            let err_str = format!("{}", result.unwrap_err());
            assert_eq!(err_str, "proprietary key decoder error: not enough bytes for decoder, 8 more bytes required");
        }

        #[test]
        fn push_bytes_incremental_push() {
            let expected = ProprietaryKey {
                prefix: "prefix".as_bytes().to_vec(),
                subtype: 2u64,
                subkeydata: TEST_SUBKEYDATA,
            };

            let bytes: Vec<u8> = vec![
                0x06, 0x70, 0x72, 0x65, 0x66, 0x69, 0x78, 0x02
            ];

            let keydata_bytes: Vec<u8> = vec![0x74, 0x65, 0x73, 0x74, 0x5f, 0x6b, 0x65, 0x79];

            let mut decoder = PsbtProprietaryKeyDecoder::new();

            for byte in bytes {
                let mut slice: &[u8] = &[byte];
                let needs_more = decoder.push_bytes(&mut slice).unwrap();

                assert!(needs_more || slice.is_empty());
            }

            let result = decoder.push_bytes(&mut keydata_bytes.as_slice()).unwrap();

            assert!(!result);

            let decoded = decoder.end().unwrap();
            assert_eq!(
                expected,
                decoded
            );
        }


        #[test]
        fn empty_slice() {
            let mut decoder = PsbtProprietaryKeyDecoder::<8>::new();
            let mut empty: &[u8] = &[];

            let result = decoder.push_bytes(&mut empty).unwrap();
            assert!(result);
        }
    }
}
