// NOTE: taken from fuchsia's `packet` library and modified, original license below:
//  Copyright 2019 The Fuchsia Authors. All rights reserved.
//  Use of this source code is governed by a BSD-style license that can be
//  found in the FUCHSIA_LICENSE file.

use zerocopy::{SplitByteSlice, SplitByteSliceMut};

use super::buffer::{BufferView, BufferViewMut, take_back, take_front};

pub trait ParsablePacket<B: SplitByteSlice, ParseArgs>: Sized {
    type Error;

    fn parse<BV: BufferView<B>>(buffer: &mut BV, args: ParseArgs) -> Result<Self, Self::Error>;

    fn parse_mut<BV: BufferViewMut<B>>(buffer: &mut BV, args: ParseArgs) -> Result<Self, Self::Error>
    where
        B: SplitByteSliceMut,
    {
        Self::parse(buffer, args)
    }
}

pub trait SerializablePacket {
    fn bytes_len(&self) -> usize;
    fn serialize<B: SplitByteSliceMut, BV: BufferViewMut<B>>(&self, buffer: &mut BV);
}

pub trait ParseBuffer {
    fn parse<'a, P: ParsablePacket<&'a [u8], ()>>(&'a mut self) -> Result<P, P::Error> {
        self.parse_with(())
    }

    fn parse_with<'a, ParseArgs, P: ParsablePacket<&'a [u8], ParseArgs>>(
        &'a mut self,
        args: ParseArgs,
    ) -> Result<P, P::Error>;
}

pub trait SerializeBuffer {
    /// Serialize a packet into this buffer.
    /// Returns a tuple of (written_portion, remaining_portion).
    fn serialize<P: SerializablePacket>(&mut self, packet: &P) -> (&mut [u8], &mut [u8]);
}

pub trait ParseBufferMut {
    fn parse_mut<'a, P: ParsablePacket<&'a mut [u8], ()>>(&'a mut self) -> Result<P, P::Error> {
        self.parse_with_mut(())
    }

    fn parse_with_mut<'a, ParseArgs, P: ParsablePacket<&'a mut [u8], ParseArgs>>(
        &'a mut self,
        args: ParseArgs,
    ) -> Result<P, P::Error>;
}

impl<'a> ParseBuffer for &'a [u8] {
    fn parse_with<'b, ParseArgs, P: ParsablePacket<&'b [u8], ParseArgs>>(
        &'b mut self,
        args: ParseArgs,
    ) -> Result<P, P::Error> {
        // A `&'b mut &'a [u8]` wrapper which implements `BufferView<&'b [u8]>`
        // instead of `BufferView<&'a [u8]>`. This is needed thanks to fact that
        // `P: ParsablePacket` has the lifetime `'b`, not `'a`.
        struct ByteSlice<'a, 'b>(&'b mut &'a [u8]);

        impl<'a, 'b> AsRef<[u8]> for ByteSlice<'a, 'b> {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl<'b, 'a: 'b> BufferView<&'b [u8]> for ByteSlice<'a, 'b> {
            fn len(&self) -> usize {
                <[u8]>::len(self.0)
            }
            fn take_front(&mut self, n: usize) -> Option<&'b [u8]> {
                if self.0.len() < n {
                    return None;
                }
                Some(take_front(self.0, n))
            }
            fn take_back(&mut self, n: usize) -> Option<&'b [u8]> {
                if self.0.len() < n {
                    return None;
                }
                Some(take_back(self.0, n))
            }
            fn into_rest(self) -> &'b [u8] {
                self.0
            }
        }

        P::parse(&mut ByteSlice(self), args)
    }
}

impl<'a> ParseBuffer for &'a mut [u8] {
    fn parse_with<'b, ParseArgs, P: ParsablePacket<&'b [u8], ParseArgs>>(
        &'b mut self,
        args: ParseArgs,
    ) -> Result<P, P::Error> {
        P::parse(&mut { self }, args)
    }
}

impl<'a> ParseBufferMut for &'a mut [u8] {
    fn parse_with_mut<'b, ParseArgs, P: ParsablePacket<&'b mut [u8], ParseArgs>>(
        &'b mut self,
        args: ParseArgs,
    ) -> Result<P, P::Error> {
        P::parse_mut(&mut { self }, args)
    }
}

impl<'a> SerializeBuffer for &'a mut [u8] {
    fn serialize<P: SerializablePacket>(&mut self, packet: &P) -> (&mut [u8], &mut [u8]) {
        let original_len = <[u8]>::len(self);
        let mut temp = &mut **self;
        packet.serialize(&mut &mut temp);
        // temp now points to remaining bytes
        let written = original_len - <[u8]>::len(&temp);
        // Split the original buffer into written and remaining portions
        let buffer = core::mem::take(self);
        let (written_portion, remaining_portion) = buffer.split_at_mut(written);
        (written_portion, remaining_portion)
    }
}
