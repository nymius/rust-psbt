//! PSBT's historic design has a reference implementation in Core re-using Core's serialization
//! framework. No matter how narrowly the bitcoin_consensus_encoding library is defined, PSBT
//! should be able to use it and that should continue to be true for all extensions of PSBT.
//!
//! However, PSBT is strictly not consensus, so the following traits expose consensus encoding for
//! PSBT without implying that PSBT depends of consensus encoding.
pub mod key;
pub mod pair;
pub mod proprietary;

/// A PSBT that can be decoded using a Core compliant push decoder.
///
/// To decode something, create a [`Self::Decoder`] and push byte slices
/// into it with [`Decoder::push_bytes`], then call [`Decoder::end`] to get the result.
pub trait PsbtDecodable {
    /// Associated decoder for the type.
    type Decoder;
    /// Constructs a "default decoder" for the type.
    fn decoder() -> Self::Decoder;
}

/// A Core compliant push decoder for PSBTs.
pub trait PsbtDecoder: Sized {
    /// The type that this decoder produces when decoding is complete.
    type Output;
    /// The error type that this decoder can produce.
    type Error;

    /// Push bytes into the decoder, consuming as much as possible.
    ///
    /// The slice reference will be advanced to point to the unconsumed portion.
    /// Returns `Ok(true)` if more bytes are needed to complete decoding,
    /// `Ok(false)` if the decoder is ready to finalize with [`Self::end`],
    /// or `Err(error)` if parsing failed.
    ///
    /// # Errors
    ///
    /// Returns an error if the provided bytes are invalid or malformed according
    /// to the decoder's validation rules. Insufficient data (needing more
    /// bytes) is *not* an error for this method, the decoder will simply consume
    /// what it can and return `true` to indicate more data is needed.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error>;

    /// Complete the decoding process and return the final result.
    ///
    /// This consumes the decoder and should be called when no more input
    /// data is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the decoder has not received sufficient data to
    /// complete decoding, or if the accumulated data is invalid when considered
    /// as a complete object.
    ///
    /// # Panics
    ///
    /// May panic if called after a previous call to [`Self::push_bytes`] errored.
    #[must_use = "must check result to avoid panics on subsequent calls"]
    fn end(self) -> Result<Self::Output, Self::Error>;

    /// Returns the maximum number of bytes this decoder can consume without over-reading.
    ///
    /// Returns 0 if the decoder is complete and ready to finalize with [`Self::end`].
    /// This is used by [`decode_from_read_unbuffered`] to optimize read sizes,
    /// avoiding both inefficient under-reads and unnecessary over-reads.
    fn read_limit(&self) -> usize;
}

/// A PSBT with Core compliant encoding.
///
/// To encode something, use the [`Self::encoder`] method to obtain a
/// [`Self::Encoder`], which will behave like an iterator yielding
/// byte slices.
pub trait PsbtEncodable {
    /// The encoder associated with this type. Conceptually, the encoder is like
    /// an iterator which yields byte slices.
    type Encoder<'e>: PsbtEncoder
    where
        Self: 'e;

    /// Constructs a "default encoder" for the type.
    fn encoder(&self) -> Self::Encoder<'_>;
}

/// An PSBT Core compliant encoder.
pub trait PsbtEncoder {
    /// Yields the current encoded byteslice.
    ///
    /// Will always return the same value until [`Self::advance`] is called. May return an empty
    /// list.
    fn current_chunk(&self) -> &[u8];

    /// Moves the encoder to its next state.
    ///
    /// Does not need to be called when the encoder is first created. (In fact, if it
    /// is called, this will discard the first chunk of encoded data.)
    ///
    /// # Returns
    ///
    /// - `true` if the encoder has advanced to a new state and [`Self::current_chunk`] will return new data.
    /// - `false` if the encoder is exhausted and has no more states.
    fn advance(&mut self) -> bool;
}
