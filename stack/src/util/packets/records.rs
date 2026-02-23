// Copyright 2019 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the FUCHSIA_LICENSE file.

//! Utilities for parsing and serializing sequential records.
//!
//! This module provides utilities for parsing and serializing repeated,
//! sequential records. Examples of packet formats which include such records
//! include IPv4, IPv6, TCP, NDP, and IGMP.
//!
//! The utilities in this module are very flexible and generic. The user must
//! supply a number of details about the format in order for parsing and
//! serializing to work.

use core::borrow::Borrow;
use core::convert::Infallible as Never;
use core::marker::PhantomData;
use core::ops::Deref;

use zerocopy::{ByteSlice, IntoByteSlice, SplitByteSlice, SplitByteSliceMut};

use super::util::MaybeParsed;
use crate::util::packets::{BufferView, BufferViewMut, SerializablePacket};

/// A type that encapsuates the result of a record parsing operation.
pub type RecordParseResult<T, E> = core::result::Result<ParsedRecord<T>, E>;

/// A type that encapsulates the successful result of a parsing operation.
pub enum ParsedRecord<T> {
    /// A record was successfully consumed and parsed.
    Parsed(T),

    /// A record was consumed but not parsed for non-fatal reasons.
    ///
    /// The caller should attempt to parse the next record to get a successfully
    /// parsed record.
    ///
    /// An example of a record that is skippable is a record used for padding.
    Skipped,

    /// All possible records have been already been consumed; there is nothing
    /// left to parse.
    ///
    /// The behavior is unspecified if callers attempt to parse another record.
    Done,
}

impl<T> ParsedRecord<T> {
    /// Does this result indicate that a record was consumed?
    ///
    /// Returns `true` for `Parsed` and `Skipped` and `false` for `Done`.
    pub fn consumed(&self) -> bool {
        match self {
            ParsedRecord::Parsed(_) | ParsedRecord::Skipped => true,
            ParsedRecord::Done => false,
        }
    }
}

/// A parsed sequence of records.
///
/// `Records` represents a pre-parsed sequence of records whose structure is
/// enforced by the impl in `R`.
#[derive(Debug, PartialEq)]
pub struct Records<B, R: RecordsImplLayout> {
    bytes: B,
    record_count: usize,
    context: R::Context,
}

/// An unchecked sequence of records.
///
/// `RecordsRaw` represents a not-yet-parsed and not-yet-validated sequence of
/// records, whose structure is enforced by the impl in `R`.
///
/// [`Records`] provides an implementation of [`FromRaw`] that can be used to
/// validate a `RecordsRaw`.
#[derive(Debug)]
pub struct RecordsRaw<B, R: RecordsImplLayout> {
    bytes: B,
    _context: R::Context,
}

impl<B, R> RecordsRaw<B, R>
where
    R: RecordsImplLayout<Context = ()>,
{
    /// Creates a new `RecordsRaw` with the data in `bytes`.
    pub fn new(bytes: B) -> Self {
        Self { bytes, _context: () }
    }
}

impl<B, R> RecordsRaw<B, R>
where
    R: for<'a> RecordsRawImpl<'a>,
    B: SplitByteSlice,
{
    /// Raw-parses a sequence of records with a context.
    ///
    /// See [`RecordsRaw::parse_raw_with_mut_context`] for details on `bytes`,
    /// `context`, and return value. `parse_raw_with_context` just calls
    /// `parse_raw_with_mut_context` with a mutable reference to the `context`
    /// which is passed by value to this function.
    pub fn parse_raw_with_context<BV: BufferView<B>>(
        bytes: &mut BV,
        mut context: R::Context,
    ) -> MaybeParsed<Self, (B, R::Error)> {
        Self::parse_raw_with_mut_context(bytes, &mut context)
    }

    /// Raw-parses a sequence of records with a mutable context.
    ///
    /// `parse_raw_with_mut_context` shallowly parses `bytes` as a sequence of
    /// records. `context` may be used by implementers to maintain state.
    ///
    /// `parse_raw_with_mut_context` performs a single pass over all of the
    /// records to be able to find the end of the records list and update
    /// `bytes` accordingly. Upon return with [`MaybeParsed::Complete`],
    /// `bytes` will include only those bytes which are not part of the records
    /// list. Upon return with [`MaybeParsed::Incomplete`], `bytes` will still
    /// contain the bytes which could not be parsed, and all subsequent bytes.
    pub fn parse_raw_with_mut_context<BV: BufferView<B>>(
        bytes: &mut BV,
        context: &mut R::Context,
    ) -> MaybeParsed<Self, (B, R::Error)> {
        let c = context.clone();
        let mut b = SplitSliceBufferView(bytes.as_ref());
        let r = loop {
            match R::parse_raw_with_context(&mut b, context) {
                Ok(true) => {} // continue consuming from data
                Ok(false) => {
                    break None;
                }
                Err(e) => {
                    break Some(e);
                }
            }
        };

        // When we get here, we know that whatever is left in `b` is not needed
        // so we only take the amount of bytes we actually need from `bytes`,
        // leaving the rest alone for the caller to continue parsing with.
        let bytes_len = bytes.len();
        let b_len = b.as_ref().len();
        let taken = bytes.take_front(bytes_len - b_len).unwrap();

        match r {
            Some(error) => MaybeParsed::Incomplete((taken, error)),
            None => MaybeParsed::Complete(RecordsRaw { bytes: taken, _context: c }),
        }
    }
}

impl<B, R> RecordsRaw<B, R>
where
    R: for<'a> RecordsRawImpl<'a> + RecordsImplLayout<Context = ()>,
    B: SplitByteSlice,
{
    /// Raw-parses a sequence of records.
    ///
    /// Equivalent to calling [`RecordsRaw::parse_raw_with_context`] with
    /// `context = ()`.
    pub fn parse_raw<BV: BufferView<B>>(bytes: &mut BV) -> MaybeParsed<Self, (B, R::Error)> {
        Self::parse_raw_with_context(bytes, ())
    }
}

impl<B, R> Deref for RecordsRaw<B, R>
where
    B: SplitByteSlice,
    R: RecordsImplLayout,
{
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.bytes.deref()
    }
}

impl<B: Deref<Target = [u8]>, R: RecordsImplLayout> RecordsRaw<B, R> {
    /// Gets the underlying bytes.
    ///
    /// `bytes` returns a reference to the byte slice backing this `RecordsRaw`.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// An iterator over the records contained inside a [`Records`] instance.
#[derive(Copy, Clone, Debug)]
pub struct RecordsIter<'a, B, R: RecordsImpl> {
    bytes: B,
    records_left: usize,
    context: R::Context,
    _marker: PhantomData<&'a ()>,
}

/// The error returned when fewer records were found than expected.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TooFewRecordsErr;

/// A counter used to keep track of how many records are remaining to be parsed.
///
/// Some record sequence formats include an indication of how many records
/// should be expected. For example, the [IGMPv3 Membership Report Message]
/// includes a "Number of Group Records" field in its header which indicates how
/// many Group Records are present following the header. A `RecordsCounter` is a
/// type used by these protocols to keep track of how many records are remaining
/// to be parsed. It is implemented for all unsigned numeric primitive types
/// (`usize`, `u8`, `u16`, `u32`, `u64`, and `u128`). A no-op implementation
/// which does not track the number of remaining records is provided for `()`.
///
/// [IGMPv3 Membership Report Message]: https://www.rfc-editor.org/rfc/rfc3376#section-4.2
pub trait RecordsCounter: Sized {
    /// The error returned from [`result_for_end_of_records`] when fewer records
    /// were found than expected.
    ///
    /// Some formats which store the number of records out-of-band consider it
    /// an error to provide fewer records than this out-of-band value.
    /// `TooFewRecordsErr` is the error returned by
    /// [`result_for_end_of_records`] when this condition is encountered. If the
    /// number of records is not tracked (usually, when `Self = ()`) or if it is
    /// not an error to provide fewer records than expected, it is recommended
    /// that `TooFewRecordsErr` be set to an uninhabited type like [`Never`].
    ///
    /// [`result_for_end_of_records`]: RecordsCounter::result_for_end_of_records
    type TooFewRecordsErr;

    /// Gets the next lowest value unless the counter is already at 0.
    ///
    /// During parsing, this value will be queried prior to parsing a record. If
    /// the counter has already reached zero (`next_lowest_value` returns
    /// `None`), parsing will be terminated. If the counter has not yet reached
    /// zero and a record is successfully parsed, the previous counter value
    /// will be overwritten with the one provided by `next_lowest_value`. In
    /// other words, the parsing logic will look something like the following
    /// pseudocode:
    ///
    /// ```rust,ignore
    /// let next = counter.next_lowest_value()?;
    /// let record = parse()?;
    /// *counter = next;
    /// ```
    ///
    /// If `Self` is a type which does not impose a limit on the number of
    /// records parsed (usually, `()`), `next_lowest_value` must always return
    /// `Some`. The value contained in the `Some` is irrelevant - it will just
    /// be written back verbatim after a record is successfully parsed.
    fn next_lowest_value(&self) -> Option<Self>;

    /// Gets a result which can be used to determine whether it is an error that
    /// there are no more records left to parse.
    ///
    /// Some formats which store the number of records out-of-band consider it
    /// an error to provide fewer records than this out-of-band value.
    /// `result_for_end_of_records` is called when there are no more records
    /// left to parse. If the counter is still at a non-zero value, and the
    /// protocol considers this to be an error, `result_for_end_of_records`
    /// should return an appropriate error. Otherwise, it should return
    /// `Ok(())`.
    fn result_for_end_of_records(&self) -> Result<(), Self::TooFewRecordsErr> {
        Ok(())
    }
}

/// The context kept while performing records parsing.
///
/// Types which implement `RecordsContext` can be used as the long-lived context
/// which is kept during records parsing. This context allows parsers to keep
/// running computations over the span of multiple records.
pub trait RecordsContext: Sized + Clone {
    /// A counter used to keep track of how many records are left to parse.
    ///
    /// See the documentation on [`RecordsCounter`] for more details.
    type Counter: RecordsCounter;

    /// Clones a context for iterator purposes.
    ///
    /// `clone_for_iter` is useful for cloning a context to be used by
    /// [`RecordsIter`]. Since [`Records::parse_with_context`] will do a full
    /// pass over all the records to check for errors, a `RecordsIter` should
    /// never error. Therefore, instead of doing checks when iterating (if a
    /// context was used for checks), a clone of a context can be made
    /// specifically for iterator purposes that does not do checks (which may be
    /// expensive).
    ///
    /// The default implementation of this method is equivalent to
    /// [`Clone::clone`].
    fn clone_for_iter(&self) -> Self {
        self.clone()
    }

    /// Gets the counter mutably.
    fn counter_mut(&mut self) -> &mut Self::Counter;
}

macro_rules! impl_records_counter_and_context_for_uxxx {
    ($ty:ty) => {
        impl RecordsCounter for $ty {
            type TooFewRecordsErr = TooFewRecordsErr;

            fn next_lowest_value(&self) -> Option<Self> {
                self.checked_sub(1)
            }

            fn result_for_end_of_records(&self) -> Result<(), TooFewRecordsErr> {
                if *self == 0 { Ok(()) } else { Err(TooFewRecordsErr) }
            }
        }

        impl RecordsContext for $ty {
            type Counter = $ty;

            fn counter_mut(&mut self) -> &mut $ty {
                self
            }
        }
    };
}

impl_records_counter_and_context_for_uxxx!(usize);
impl_records_counter_and_context_for_uxxx!(u128);
impl_records_counter_and_context_for_uxxx!(u64);
impl_records_counter_and_context_for_uxxx!(u32);
impl_records_counter_and_context_for_uxxx!(u16);
impl_records_counter_and_context_for_uxxx!(u8);

impl RecordsCounter for () {
    type TooFewRecordsErr = Never;

    fn next_lowest_value(&self) -> Option<()> {
        Some(())
    }
}

impl RecordsContext for () {
    type Counter = ();

    fn counter_mut(&mut self) -> &mut () {
        self
    }
}

/// Basic associated types used by a [`RecordsImpl`].
///
/// This trait is kept separate from `RecordsImpl` so that the associated types
/// do not depend on the lifetime parameter to `RecordsImpl`.
pub trait RecordsImplLayout {
    // TODO(https://github.com/rust-lang/rust/issues/29661): Give the `Context`
    // type a default of `()`.

    /// A context type that can be used to maintain state while parsing multiple
    /// records.
    type Context: RecordsContext;

    /// The type of errors that may be returned by a call to
    /// [`RecordsImpl::parse_with_context`].
    type Error: From<<<Self::Context as RecordsContext>::Counter as RecordsCounter>::TooFewRecordsErr>;
}

/// An implementation of a records parser.
///
/// `RecordsImpl` provides functions to parse sequential records. It is required
///  in order to construct a [`Records`] or [`RecordsIter`].
pub trait RecordsImpl: RecordsImplLayout {
    /// The type of a single record; the output from the [`parse_with_context`]
    /// function.
    ///
    /// For long or variable-length data, implementers are advised to make
    /// `Record` a reference into the bytes passed to `parse_with_context`. Such
    /// a reference will need to carry the lifetime `'a`, which is the same
    /// lifetime that is passed to `parse_with_context`, and is also the
    /// lifetime parameter to this trait.
    ///
    /// [`parse_with_context`]: RecordsImpl::parse_with_context
    type Record<'a>;

    /// Parses a record with some context.
    ///
    /// `parse_with_context` takes a variable-length `data` and a `context` to
    /// maintain state.
    ///
    /// `data` may be empty. It is up to the implementer to handle an exhausted
    /// `data`.
    ///
    /// When returning `Ok(ParsedRecord::Skipped)`, it's the implementer's
    /// responsibility to consume the bytes of the record from `data`. If this
    /// doesn't happen, then `parse_with_context` will be called repeatedly on
    /// the same `data`, and the program will be stuck in an infinite loop. If
    /// the implementation is unable to determine how many bytes to consume from
    /// `data` in order to skip the record, `parse_with_context` must return
    /// `Err`.
    ///
    /// `parse_with_context` must be deterministic, or else
    /// [`Records::parse_with_context`] cannot guarantee that future iterations
    /// will not produce errors (and thus panic).
    fn parse_with_context<'a, BV: BufferView<&'a [u8]>>(
        data: &mut BV,
        context: &mut Self::Context,
    ) -> RecordParseResult<Self::Record<'a>, Self::Error>;
}

/// An implementation of a raw records parser.
///
/// `RecordsRawImpl` provides functions to raw-parse sequential records. It is
/// required to construct a partially-parsed [`RecordsRaw`].
///
/// `RecordsRawImpl` is meant to perform little or no validation on each record
/// it consumes. It is primarily used to be able to walk record sequences with
/// unknown lengths.
pub trait RecordsRawImpl<'a>: RecordsImplLayout {
    /// Raw-parses a single record with some context.
    ///
    /// `parse_raw_with_context` takes a variable length `data` and a `context`
    /// to maintain state, and returns `Ok(true)` if a record is successfully
    /// consumed, `Ok(false)` if it is unable to parse more records, and
    /// `Err(err)` if the `data` is malformed in any way.
    ///
    /// `data` may be empty. It is up to the implementer to handle an exhausted
    /// `data`.
    ///
    /// It's the implementer's responsibility to consume exactly one record from
    /// `data` when returning `Ok(_)`.
    fn parse_raw_with_context<BV: BufferView<&'a [u8]>>(
        data: &mut BV,
        context: &mut Self::Context,
    ) -> Result<bool, Self::Error>;
}

/// A builder capable of serializing a record.
///
/// Given `R: RecordBuilder`, an iterator of `R` can be used with a
/// [`RecordSequenceBuilder`] to serialize a sequence of records.
pub trait RecordBuilder {
    /// Provides the serialized length of a record.
    ///
    /// Returns the total length, in bytes, of the serialized encoding of
    /// `self`.
    fn serialized_len(&self) -> usize;

    /// Serializes `self` into a buffer.
    ///
    /// `data` will be exactly `self.serialized_len()` bytes long.
    ///
    /// # Panics
    ///
    /// May panic if `data` is not exactly `self.serialized_len()` bytes long.
    fn serialize_into(&self, data: &mut [u8]);
}

/// A builder capable of serializing a sequence of records.
///
/// A `RecordSequenceBuilder` is instantiated with an [`Iterator`] that provides
/// [`RecordBuilder`]s to be serialized. The item produced by the iterator can
/// be any type which implements `Borrow<R>` for `R: RecordBuilder`.
///
/// `RecordSequenceBuilder` implements [`SerializablePacket`].
#[derive(Debug, Clone)]
pub struct RecordSequenceBuilder<R, I> {
    records: I,
    _marker: PhantomData<R>,
}

impl<R, I> RecordSequenceBuilder<R, I> {
    /// Creates a new `RecordSequenceBuilder` with the given `records`.
    ///
    /// `records` must produce the same sequence of values from every iteration,
    /// even if cloned. Serialization is typically performed with two passes on
    /// `records`: one to calculate the total length in bytes (`serialized_len`)
    /// and another one to serialize to a buffer (`serialize_into`). Violating
    /// this rule may result in panics or malformed serialized record sequences.
    pub fn new(records: I) -> Self {
        Self { records, _marker: PhantomData }
    }
}

impl<R, I> RecordSequenceBuilder<R, I>
where
    R: RecordBuilder,
    I: Iterator + Clone,
    I::Item: Borrow<R>,
{
    /// Returns the total length, in bytes, of the serialized encoding of the
    /// records contained within `self`.
    pub fn serialized_len(&self) -> usize {
        self.records.clone().map(|r| r.borrow().serialized_len()).sum()
    }

    /// Serializes all the records contained within `self` into the given
    /// buffer.
    ///
    /// # Panics
    ///
    /// `serialize_into` expects that `buffer` has enough bytes to serialize the
    /// contained records (as obtained from `serialized_len`), otherwise it's
    /// considered a violation of the API contract and the call may panic.
    pub fn serialize_into(&self, buffer: &mut [u8]) {
        let mut b = &mut &mut buffer[..];
        for r in self.records.clone() {
            // SECURITY: Take a zeroed buffer from b to prevent leaking
            // information from packets previously stored in this buffer.
            r.borrow().serialize_into(b.take_front_zero(r.borrow().serialized_len()).unwrap());
        }
    }

    /// Returns a reference to the inner records of this builder.
    pub fn records(&self) -> &I {
        &self.records
    }
}

impl<R, I> SerializablePacket for RecordSequenceBuilder<R, I>
where
    R: RecordBuilder,
    I: Iterator + Clone,
    I::Item: Borrow<R>,
{
    fn bytes_len(&self) -> usize {
        self.serialized_len()
    }

    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, bv: &mut BV) {
        // Properly consume bytes from the BufferView for each record
        for record in self.records.clone() {
            let record = record.borrow();
            let len = record.serialized_len();
            let mut slice = bv.take_front_zero(len).expect("insufficient buffer space for record");
            record.serialize_into(slice.as_mut());
        }
    }
}

impl<B, R> Records<B, R>
where
    B: SplitByteSlice,
    R: RecordsImpl,
{
    /// Parses a sequence of records with a context.
    ///
    /// See [`parse_with_mut_context`] for details on `bytes`, `context`, and
    /// return value. `parse_with_context` just calls `parse_with_mut_context`
    /// with a mutable reference to the `context` which is passed by value to
    /// this function.
    ///
    /// [`parse_with_mut_context`]: Records::parse_with_mut_context
    pub fn parse_with_context(bytes: B, mut context: R::Context) -> Result<Records<B, R>, R::Error> {
        Self::parse_with_mut_context(bytes, &mut context)
    }

    /// Parses a sequence of records with a mutable context.
    ///
    /// `context` may be used by implementers to maintain state while parsing
    /// multiple records.
    ///
    /// `parse_with_mut_context` performs a single pass over all of the records
    /// to verify that they are well-formed. Once `parse_with_context` returns
    /// successfully, the resulting `Records` can be used to construct
    /// infallible iterators.
    pub fn parse_with_mut_context(bytes: B, context: &mut R::Context) -> Result<Records<B, R>, R::Error> {
        // First, do a single pass over the bytes to detect any errors up front.
        // Once this is done, since we have a reference to `bytes`, these bytes
        // can't change out from under us, and so we can treat any iterator over
        // these bytes as infallible. This makes a few assumptions, but none of
        // them are that big of a deal. In all cases, breaking these assumptions
        // would at worst result in a runtime panic.
        // - B could return different bytes each time
        // - R::parse could be non-deterministic
        let c = context.clone();
        let mut b = SplitSliceBufferView(bytes.as_ref());
        let mut record_count = 0;
        while next::<_, R>(&mut b, context)?.is_some() {
            record_count += 1;
        }
        Ok(Records { bytes, record_count, context: c })
    }
}

impl<B, R> Records<B, R>
where
    B: SplitByteSlice,
    R: RecordsImpl<Context = ()>,
{
    /// Parses a sequence of records.
    ///
    /// Equivalent to calling [`parse_with_context`] with `context = ()`.
    ///
    /// [`parse_with_context`]: Records::parse_with_context
    pub fn parse(bytes: B) -> Result<Records<B, R>, R::Error> {
        Self::parse_with_context(bytes, ())
    }
}

impl<B: Deref<Target = [u8]>, R> Records<B, R>
where
    R: RecordsImpl,
{
    /// Gets the underlying bytes.
    ///
    /// `bytes` returns a reference to the byte slice backing this `Records`.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<B, R> Records<B, R>
where
    B: ByteSlice,
    R: RecordsImpl,
{
    /// Returns the same records but coerces the backing `B` type to `&[u8]`.
    pub fn as_ref(&self) -> Records<&[u8], R> {
        let Self { bytes, record_count, context } = self;
        Records { bytes: bytes, record_count: *record_count, context: context.clone() }
    }
}

impl<'a, B, R> Records<B, R>
where
    B: 'a + SplitByteSlice,
    R: RecordsImpl,
{
    /// Iterates over options.
    ///
    /// Since the records were validated in [`parse`], then so long as
    /// [`R::parse_with_context`] is deterministic, the iterator is infallible.
    ///
    /// [`parse`]: Records::parse
    /// [`R::parse_with_context`]: RecordsImpl::parse_with_context
    pub fn iter(&'a self) -> RecordsIter<'a, &'a [u8], R> {
        RecordsIter {
            bytes: &self.bytes,
            records_left: self.record_count,
            context: self.context.clone_for_iter(),
            _marker: PhantomData,
        }
    }
}

impl<'a, B, R> Records<B, R>
where
    B: SplitByteSlice + IntoByteSlice<'a>,
    R: RecordsImpl,
{
    /// Iterates over options.
    ///
    /// Since the records were validated in [`parse`], then so long as
    /// [`R::parse_with_context`] is deterministic, the iterator is infallible.
    ///
    /// [`parse`]: Records::parse
    /// [`R::parse_with_context`]: RecordsImpl::parse_with_context
    pub fn into_iter(self) -> RecordsIter<'a, B, R> {
        RecordsIter { bytes: self.bytes, records_left: self.record_count, context: self.context, _marker: PhantomData }
    }
}

impl<'a, B, R> RecordsIter<'a, B, R>
where
    R: RecordsImpl,
{
    /// Gets a reference to the context.
    pub fn context(&self) -> &R::Context {
        &self.context
    }
}

impl<'a, B, R> Iterator for RecordsIter<'a, B, R>
where
    R: RecordsImpl,
    B: SplitByteSlice + IntoByteSlice<'a>,
{
    type Item = R::Record<'a>;

    fn next(&mut self) -> Option<R::Record<'a>> {
        replace_with::replace_with_or_abort_and_return(&mut self.bytes, |bytes| {
            let mut bytes = SplitSliceBufferView(bytes);
            // use match rather than expect because expect requires that Err: Debug
            #[allow(clippy::match_wild_err_arm)]
            let result = match next::<_, R>(&mut bytes, &mut self.context) {
                Ok(o) => o,
                Err(_) => panic!("already-validated options should not fail to parse"),
            };
            if result.is_some() {
                self.records_left -= 1;
            }
            let SplitSliceBufferView(bytes) = bytes;
            (result, bytes)
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.records_left, Some(self.records_left))
    }
}

impl<'a, B, R> ExactSizeIterator for RecordsIter<'a, B, R>
where
    R: RecordsImpl,
    B: SplitByteSlice + IntoByteSlice<'a>,
{
    fn len(&self) -> usize {
        self.records_left
    }
}

/// Gets the next entry for a set of sequential records in `bytes`.
///
/// On return, `bytes` will be pointing to the start of where a next record
/// would be.
fn next<'a, BV, R>(bytes: &mut BV, context: &mut R::Context) -> Result<Option<R::Record<'a>>, R::Error>
where
    R: RecordsImpl,
    BV: BufferView<&'a [u8]>,
{
    loop {
        // If we're already at 0, don't attempt to parse any more records.
        let next_lowest_counter_val = match context.counter_mut().next_lowest_value() {
            Some(val) => val,
            None => return Ok(None),
        };
        match R::parse_with_context(bytes, context)? {
            ParsedRecord::Done => {
                return context.counter_mut().result_for_end_of_records().map_err(Into::into).map(|()| None);
            }
            ParsedRecord::Skipped => {}
            ParsedRecord::Parsed(o) => {
                *context.counter_mut() = next_lowest_counter_val;
                return Ok(Some(o));
            }
        }
    }
}

struct SplitSliceBufferView<B>(B);

impl<B: SplitByteSlice> AsRef<[u8]> for SplitSliceBufferView<B> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a, B: SplitByteSlice + IntoByteSlice<'a>> BufferView<&'a [u8]> for SplitSliceBufferView<B> {
    fn take_front(&mut self, n: usize) -> Option<&'a [u8]> {
        replace_with::replace_with_or_abort_and_return(&mut self.0, |bytes| match bytes.split_at(n) {
            Ok((prefix, suffix)) => (Some(prefix.into_byte_slice()), suffix),
            Err(e) => (None, e),
        })
    }

    fn take_back(&mut self, n: usize) -> Option<&'a [u8]> {
        replace_with::replace_with_or_abort_and_return(&mut self.0, |bytes| match bytes.split_at(n) {
            Ok((prefix, suffix)) => (Some(suffix.into_byte_slice()), prefix),
            Err(e) => (None, e),
        })
    }

    fn into_rest(self) -> &'a [u8] {
        self.0.into_byte_slice()
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;
    use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, Unaligned};

    use super::*;

    const DUMMY_BYTES: [u8; 16] =
        [0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04];

    fn get_empty_tuple_mut_ref<'a>() -> &'a mut () {
        // This is a hack since `&mut ()` is invalid.
        let bytes: &mut [u8] = &mut [];
        zerocopy::Ref::into_mut(zerocopy::Ref::<_, ()>::from_bytes(bytes).unwrap())
    }

    #[derive(Debug, IntoBytes, KnownLayout, FromBytes, Immutable, Unaligned)]
    #[repr(C)]
    struct DummyRecord {
        a: [u8; 2],
        b: u8,
        c: u8,
    }

    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    enum DummyRecordErr {
        Parse,
        TooFewRecords,
    }

    impl From<Never> for DummyRecordErr {
        fn from(err: Never) -> DummyRecordErr {
            match err {}
        }
    }

    impl From<TooFewRecordsErr> for DummyRecordErr {
        fn from(_: TooFewRecordsErr) -> DummyRecordErr {
            DummyRecordErr::TooFewRecords
        }
    }

    fn parse_dummy_rec<'a, BV>(data: &mut BV) -> RecordParseResult<Ref<&'a [u8], DummyRecord>, DummyRecordErr>
    where
        BV: BufferView<&'a [u8]>,
    {
        if data.is_empty() {
            return Ok(ParsedRecord::Done);
        }

        match data.take_obj_front::<DummyRecord>() {
            Some(res) => Ok(ParsedRecord::Parsed(res)),
            None => Err(DummyRecordErr::Parse),
        }
    }

    //
    // Context-less records
    //

    #[derive(Debug)]
    struct ContextlessRecordImpl;

    impl RecordsImplLayout for ContextlessRecordImpl {
        type Context = ();
        type Error = DummyRecordErr;
    }

    impl RecordsImpl for ContextlessRecordImpl {
        type Record<'a> = Ref<&'a [u8], DummyRecord>;

        fn parse_with_context<'a, BV: BufferView<&'a [u8]>>(
            data: &mut BV,
            _context: &mut Self::Context,
        ) -> RecordParseResult<Self::Record<'a>, Self::Error> {
            parse_dummy_rec(data)
        }
    }

    //
    // Limit context records
    //

    #[derive(Debug)]
    struct LimitContextRecordImpl;

    impl RecordsImplLayout for LimitContextRecordImpl {
        type Context = usize;
        type Error = DummyRecordErr;
    }

    impl RecordsImpl for LimitContextRecordImpl {
        type Record<'a> = Ref<&'a [u8], DummyRecord>;

        fn parse_with_context<'a, BV: BufferView<&'a [u8]>>(
            data: &mut BV,
            _context: &mut usize,
        ) -> RecordParseResult<Self::Record<'a>, Self::Error> {
            parse_dummy_rec(data)
        }
    }

    //
    // Filter context records
    //

    #[derive(Debug)]
    struct FilterContextRecordImpl;

    #[derive(Clone)]
    struct FilterContext {
        pub disallowed: [bool; 256],
    }

    impl RecordsContext for FilterContext {
        type Counter = ();
        fn counter_mut(&mut self) -> &mut () {
            get_empty_tuple_mut_ref()
        }
    }

    impl RecordsImplLayout for FilterContextRecordImpl {
        type Context = FilterContext;
        type Error = DummyRecordErr;
    }

    impl core::fmt::Debug for FilterContext {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "FilterContext{{disallowed:{:?}}}", &self.disallowed[..])
        }
    }

    impl RecordsImpl for FilterContextRecordImpl {
        type Record<'a> = Ref<&'a [u8], DummyRecord>;

        fn parse_with_context<'a, BV: BufferView<&'a [u8]>>(
            bytes: &mut BV,
            context: &mut Self::Context,
        ) -> RecordParseResult<Self::Record<'a>, Self::Error> {
            if bytes.len() < core::mem::size_of::<DummyRecord>() {
                Ok(ParsedRecord::Done)
            } else if bytes.as_ref()[0..core::mem::size_of::<DummyRecord>()]
                .iter()
                .any(|x| context.disallowed[*x as usize])
            {
                Err(DummyRecordErr::Parse)
            } else {
                parse_dummy_rec(bytes)
            }
        }
    }

    //
    // Stateful context records
    //

    #[derive(Debug)]
    struct StatefulContextRecordImpl;

    #[derive(Clone, Debug)]
    struct StatefulContext {
        pub pre_parse_counter: usize,
        pub parse_counter: usize,
        pub post_parse_counter: usize,
        pub iter: bool,
    }

    impl RecordsImplLayout for StatefulContextRecordImpl {
        type Context = StatefulContext;
        type Error = DummyRecordErr;
    }

    impl StatefulContext {
        pub fn new() -> StatefulContext {
            StatefulContext { pre_parse_counter: 0, parse_counter: 0, post_parse_counter: 0, iter: false }
        }
    }

    impl RecordsContext for StatefulContext {
        type Counter = ();

        fn clone_for_iter(&self) -> Self {
            let mut x = self.clone();
            x.iter = true;
            x
        }

        fn counter_mut(&mut self) -> &mut () {
            get_empty_tuple_mut_ref()
        }
    }

    impl RecordsImpl for StatefulContextRecordImpl {
        type Record<'a> = Ref<&'a [u8], DummyRecord>;

        fn parse_with_context<'a, BV: BufferView<&'a [u8]>>(
            data: &mut BV,
            context: &mut Self::Context,
        ) -> RecordParseResult<Self::Record<'a>, Self::Error> {
            if !context.iter {
                context.pre_parse_counter += 1;
            }

            let ret = parse_dummy_rec_with_context(data, context);

            if let Ok(ParsedRecord::Parsed(_)) = ret {
                if !context.iter {
                    context.post_parse_counter += 1;
                }
            }

            ret
        }
    }

    impl<'a> RecordsRawImpl<'a> for StatefulContextRecordImpl {
        fn parse_raw_with_context<BV: BufferView<&'a [u8]>>(
            data: &mut BV,
            context: &mut Self::Context,
        ) -> Result<bool, Self::Error> {
            Self::parse_with_context(data, context).map(|r| r.consumed())
        }
    }

    fn parse_dummy_rec_with_context<'a, BV>(
        data: &mut BV,
        context: &mut StatefulContext,
    ) -> RecordParseResult<Ref<&'a [u8], DummyRecord>, DummyRecordErr>
    where
        BV: BufferView<&'a [u8]>,
    {
        if data.is_empty() {
            return Ok(ParsedRecord::Done);
        }

        if !context.iter {
            context.parse_counter += 1;
        }

        match data.take_obj_front::<DummyRecord>() {
            Some(res) => Ok(ParsedRecord::Parsed(res)),
            None => Err(DummyRecordErr::Parse),
        }
    }

    fn check_parsed_record(rec: &DummyRecord) {
        assert_eq!(rec.a[0], 0x01);
        assert_eq!(rec.a[1], 0x02);
        assert_eq!(rec.b, 0x03);
    }

    fn validate_parsed_stateful_context_records<B: SplitByteSlice>(
        records: Records<B, StatefulContextRecordImpl>,
        context: StatefulContext,
    ) {
        // Should be 5 because on the last iteration, we should realize that we
        // have no more bytes left and end before parsing (also explaining why
        // `parse_counter` should only be 4.
        assert_eq!(context.pre_parse_counter, 5);
        assert_eq!(context.parse_counter, 4);
        assert_eq!(context.post_parse_counter, 4);

        let mut iter = records.iter();
        let context = &iter.context;
        assert_eq!(context.pre_parse_counter, 0);
        assert_eq!(context.parse_counter, 0);
        assert_eq!(context.post_parse_counter, 0);
        assert_eq!(context.iter, true);

        // Manually iterate over `iter` so as to not move it.
        let mut count = 0;
        while let Some(_) = iter.next() {
            count += 1;
        }
        assert_eq!(count, 4);

        // Check to see that when iterating, the context doesn't update counters
        // as that is how we implemented our StatefulContextRecordImpl..
        let context = &iter.context;
        assert_eq!(context.pre_parse_counter, 0);
        assert_eq!(context.parse_counter, 0);
        assert_eq!(context.post_parse_counter, 0);
        assert_eq!(context.iter, true);
    }

    #[test]
    fn all_records_parsing() {
        let parsed = Records::<_, ContextlessRecordImpl>::parse(&DUMMY_BYTES[..]).unwrap();
        let mut iter = parsed.iter();
        // Test ExactSizeIterator implementation.
        assert_eq!(iter.len(), 4);
        let mut cnt = 4;
        while let Some(_) = iter.next() {
            cnt -= 1;
            assert_eq!(iter.len(), cnt);
        }
        assert_eq!(iter.len(), 0);
        for rec in parsed.iter() {
            check_parsed_record(rec.deref());
        }
    }

    // `expect` is either the number of records that should have been parsed or
    // the error returned from the `Records` constructor.
    //
    // If there are more records than the limit, then we just truncate (not
    // parsing all of them) and don't return an error.
    #[test_case(0, Ok(0))]
    #[test_case(1, Ok(1))]
    #[test_case(2, Ok(2))]
    #[test_case(3, Ok(3))]
    // If there are the same number of records as the limit, then we
    // succeed.
    #[test_case(4, Ok(4))]
    // If there are fewer records than the limit, then we fail.
    #[test_case(5, Err(DummyRecordErr::TooFewRecords))]
    fn limit_records_parsing(limit: usize, expect: Result<usize, DummyRecordErr>) {
        // Test without mutable limit/context
        let check_result = |result: Result<Records<_, LimitContextRecordImpl>, _>| match (expect, result) {
            (Ok(expect_parsed), Ok(records)) => {
                assert_eq!(records.iter().count(), expect_parsed);
                for rec in records.iter() {
                    check_parsed_record(rec.deref());
                }
            }
            (Err(expect), Err(got)) => assert_eq!(expect, got),
            (Ok(expect_parsed), Err(err)) => {
                panic!("wanted {expect_parsed} successfully-parsed records; got error {err:?}")
            }
            (Err(expect), Ok(records)) => {
                panic!("wanted error {expect:?}, got {} successfully-parsed records", records.iter().count())
            }
        };

        check_result(Records::<_, LimitContextRecordImpl>::parse_with_context(&DUMMY_BYTES[..], limit));
        let mut mut_limit = limit;
        check_result(Records::<_, LimitContextRecordImpl>::parse_with_mut_context(&DUMMY_BYTES[..], &mut mut_limit));
        if let Ok(expect_parsed) = expect {
            assert_eq!(limit - mut_limit, expect_parsed);
        }
    }

    #[test]
    fn context_filtering_some_byte_records_parsing() {
        // Do not disallow any bytes
        let context = FilterContext { disallowed: [false; 256] };
        let parsed = Records::<_, FilterContextRecordImpl>::parse_with_context(&DUMMY_BYTES[..], context).unwrap();
        assert_eq!(parsed.iter().count(), 4);
        for rec in parsed.iter() {
            check_parsed_record(rec.deref());
        }

        // Do not allow byte value 0x01
        let mut context = FilterContext { disallowed: [false; 256] };
        context.disallowed[1] = true;
        assert_eq!(
            Records::<_, FilterContextRecordImpl>::parse_with_context(&DUMMY_BYTES[..], context)
                .expect_err("fails if the buffer has an element with value 0x01"),
            DummyRecordErr::Parse
        );
    }

    #[test]
    fn stateful_context_records_parsing() {
        let mut context = StatefulContext::new();
        let parsed =
            Records::<_, StatefulContextRecordImpl>::parse_with_mut_context(&DUMMY_BYTES[..], &mut context).unwrap();
        validate_parsed_stateful_context_records(parsed, context);
    }

    #[test]
    fn raw_parse_failure() {
        let mut context = StatefulContext::new();
        let mut bv = &mut &DUMMY_BYTES[0..15];
        let result = RecordsRaw::<_, StatefulContextRecordImpl>::parse_raw_with_mut_context(&mut bv, &mut context)
            .incomplete()
            .unwrap();
        assert_eq!(result, (&DUMMY_BYTES[0..12], DummyRecordErr::Parse));
    }
}
