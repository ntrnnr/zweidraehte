//! Buffer management and views into buffers

// NOTE: taken from fuchsia's `packet` library and modified:
// We just a have a less awesome API, because we removed the BufViews and implement
// the BufferView and BufferViewMut traits directly on Buf, otherwise we can't use Yoke

use core::mem;
use core::ops::{Bound, Range, RangeBounds};

use zerocopy::{
    ByteSlice, ByteSliceMut, FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Ref,
    Unaligned,
};

pub trait BufferView<B: ByteSlice>: Sized + AsRef<[u8]> {
    fn len(&self) -> usize {
        self.as_ref().len()
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn take_front(&mut self, n: usize) -> Option<B>;
    fn take_back(&mut self, n: usize) -> Option<B>;

    fn take_rest_front(&mut self) -> B {
        let len = self.len();
        self.take_front(len).unwrap()
    }

    fn take_rest_back(&mut self) -> B {
        let len = self.len();
        self.take_back(len).unwrap()
    }

    fn take_byte_front(&mut self) -> Option<u8> {
        self.take_front(1).map(|x| x[0])
    }

    fn take_byte_back(&mut self) -> Option<u8> {
        self.take_back(1).map(|x| x[0])
    }

    fn into_rest(self) -> B;

    fn peek_obj_front<T>(&self) -> Option<&T>
    where
        T: FromBytes + KnownLayout + Immutable + Unaligned,
    {
        Some(Ref::into_ref(
            Ref::<_, T>::from_prefix(self.as_ref()).ok()?.0,
        ))
    }

    fn take_obj_front<T>(&mut self) -> Option<Ref<B, T>>
    where
        T: KnownLayout + Immutable + Unaligned,
    {
        let bytes = self.take_front(mem::size_of::<T>())?;
        // unaligned_from_bytes only returns None if there aren't enough bytes
        Some(Ref::from_bytes(bytes).unwrap())
    }

    fn take_slice_front<T>(&mut self, n: usize) -> Option<Ref<B, [T]>>
    where
        T: Immutable + Unaligned,
    {
        let bytes = self.take_front(n * mem::size_of::<T>())?;
        // `unaligned_from_bytes` will return `None` only if `bytes.len()` is
        // not a multiple of `mem::size_of::<T>()`.
        Some(Ref::from_bytes(bytes).unwrap())
    }

    fn peek_obj_back<T>(&mut self) -> Option<&T>
    where
        T: FromBytes + KnownLayout + Immutable + Unaligned,
    {
        Some(Ref::into_ref(
            Ref::<_, T>::from_suffix((&*self).as_ref()).ok()?.1,
        ))
    }

    fn take_obj_back<T>(&mut self) -> Option<Ref<B, T>>
    where
        T: Immutable + KnownLayout + Unaligned,
    {
        let bytes = self.take_back(mem::size_of::<T>())?;
        // new_unaligned only returns None if there aren't enough bytes
        Some(Ref::from_bytes(bytes).unwrap())
    }

    fn take_slice_back<T>(&mut self, n: usize) -> Option<Ref<B, [T]>>
    where
        T: Immutable + Unaligned,
    {
        let bytes = self.take_back(n * mem::size_of::<T>())?;
        // `new_slice_unaligned` will return `None` only if `bytes.len()` is
        // not a multiple of `mem::size_of::<T>()`.
        Some(Ref::from_bytes(bytes).unwrap())
    }
}

pub trait BufferViewMut<B: ByteSliceMut>: BufferView<B> + AsMut<[u8]> {
    fn take_front_zero(&mut self, n: usize) -> Option<B> {
        self.take_front(n).map(|mut buf| {
            zero(buf.deref_mut());
            buf
        })
    }

    fn take_back_zero(&mut self, n: usize) -> Option<B> {
        self.take_back(n).map(|mut buf| {
            zero(buf.deref_mut());
            buf
        })
    }

    fn take_rest_front_zero(mut self) -> B {
        let len = self.len();
        self.take_front_zero(len).unwrap()
    }

    fn take_rest_back_zero(mut self) -> B {
        let len = self.len();
        self.take_front_zero(len).unwrap()
    }

    fn into_rest_zero(self) -> B {
        let mut bytes = self.into_rest();
        zero(&mut bytes);
        bytes
    }

    fn take_obj_front_zero<T>(&mut self) -> Option<Ref<B, T>>
    where
        T: KnownLayout + Immutable + Unaligned,
    {
        let bytes = self.take_front(mem::size_of::<T>())?;
        // unaligned_from_bytes only returns None if there aren't enough bytes
        let mut obj: Ref<_, _> = Ref::from_bytes(bytes).unwrap();
        Ref::bytes_mut(&mut obj).zero();
        Some(obj)
    }

    fn take_obj_back_zero<T>(&mut self) -> Option<Ref<B, T>>
    where
        T: KnownLayout + Immutable + Unaligned,
    {
        let bytes = self.take_back(mem::size_of::<T>())?;
        // unaligned_from_bytes only returns None if there aren't enough bytes
        let mut obj: Ref<_, _> = Ref::from_bytes(bytes).unwrap();
        Ref::bytes_mut(&mut obj).zero();
        Some(obj)
    }

    fn write_obj_front<T>(&mut self, obj: &T) -> Option<()>
    where
        T: ?Sized + IntoBytes + Immutable,
    {
        let mut bytes = self.take_front(mem::size_of_val(obj))?;
        bytes.copy_from_slice(obj.as_bytes());
        Some(())
    }

    fn write_obj_back<T>(&mut self, obj: &T) -> Option<()>
    where
        T: ?Sized + IntoBytes + Immutable,
    {
        let mut bytes = self.take_back(mem::size_of_val(obj))?;
        bytes.copy_from_slice(obj.as_bytes());
        Some(())
    }
}

#[derive(Clone, Debug)]
pub struct Buf<B> {
    buf: B,
    body: Range<usize>,
}

impl<B: AsRef<[u8]>> Buf<B> {
    pub fn new<R: RangeBounds<usize>>(buf: B, body: R) -> Buf<B> {
        let len = buf.as_ref().len();
        Buf {
            buf,
            body: canonicalize_range(len, &body),
        }
    }
}

impl<'a> BufferView<&'a [u8]> for Buf<&'a [u8]> {
    fn take_front(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.len() < n {
            return None;
        }

        let s = self.body.start;
        self.body.start += n;

        Some(&self.buf[s..s + n])
    }

    fn take_back(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.len() < n {
            return None;
        }

        let e = self.body.end;
        self.body.end -= n;

        Some(&self.buf[self.body.end..e])
    }

    fn into_rest(self) -> &'a [u8] {
        &self.buf[self.body]
    }
}

// // FIXME: make it work in Buf<Vec<u8>> directly
// impl<'a> BufferView<&'a [u8]> for Buf<Vec<u8>> {
//     fn take_front(&mut self, n: usize) -> Option<&'a [u8]> {
//         Some(&self.buf[0..1])
//     }

//     fn take_back(&mut self, n: usize) -> Option<&'a [u8]> {
//         Some(&self.buf[0..1])
//     }

//     fn into_rest(self) -> &'a [u8] {
//         &self.buf[self.body.clone()]
//     }
// }

impl<B: core::ops::Deref<Target = [u8]>> AsRef<[u8]> for Buf<B> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[self.body.clone()]
    }
}

fn zero(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        *byte = 0;
    }
}

fn canonicalize_range<R: RangeBounds<usize>>(len: usize, range: &R) -> Range<usize> {
    let lower = canonicalize_lower_bound(range.start_bound());
    let upper = canonicalize_upper_bound(len, range.end_bound()).expect("range out of bounds");
    assert!(
        lower <= upper,
        "invalid range: upper bound precedes lower bound"
    );
    lower..upper
}

fn canonicalize_lower_bound(bound: Bound<&usize>) -> usize {
    match bound {
        Bound::Included(x) => *x,
        Bound::Excluded(x) => *x + 1,
        Bound::Unbounded => 0,
    }
}

fn canonicalize_upper_bound(len: usize, bound: Bound<&usize>) -> Option<usize> {
    let bound = match bound {
        Bound::Included(x) => *x + 1,
        Bound::Excluded(x) => *x,
        Bound::Unbounded => len,
    };

    if bound > len {
        return None;
    }

    Some(bound)
}

impl<'b, 'a: 'b> BufferView<&'a [u8]> for &'b mut &'a [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn take_front(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.len() < n {
            return None;
        }

        Some(take_front(self, n))
    }

    fn take_back(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.len() < n {
            return None;
        }

        Some(take_back(self, n))
    }

    fn into_rest(self) -> &'a [u8] {
        self
    }
}

impl<'b, 'a: 'b> BufferView<&'b [u8]> for &'b mut &'a mut [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn take_front(&mut self, n: usize) -> Option<&'b [u8]> {
        if <[u8]>::len(self) < n {
            return None;
        }
        Some(take_front_mut(self, n))
    }

    fn take_back(&mut self, n: usize) -> Option<&'b [u8]> {
        if <[u8]>::len(self) < n {
            return None;
        }
        Some(take_back_mut(self, n))
    }

    fn into_rest(self) -> &'b [u8] {
        self
    }
}

impl<'b, 'a: 'b> BufferView<&'b mut [u8]> for &'b mut &'a mut [u8] {
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }

    fn take_front(&mut self, n: usize) -> Option<&'b mut [u8]> {
        if <[u8]>::len(self) < n {
            return None;
        }
        Some(take_front_mut(self, n))
    }

    fn take_back(&mut self, n: usize) -> Option<&'b mut [u8]> {
        if <[u8]>::len(self) < n {
            return None;
        }
        Some(take_back_mut(self, n))
    }

    fn into_rest(self) -> &'b mut [u8] {
        self
    }
}

impl<'b, 'a: 'b> BufferViewMut<&'b mut [u8]> for &'b mut &'a mut [u8] {}

fn take_front<'a>(bytes: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (prefix, rest) = mem::replace(bytes, &[]).split_at(n);
    *bytes = rest;
    prefix
}

fn take_back<'a>(bytes: &mut &'a [u8], n: usize) -> &'a [u8] {
    let split = bytes.len() - n;
    let (rest, suffix) = mem::replace(bytes, &[]).split_at(split);
    *bytes = rest;
    suffix
}

fn take_front_mut<'a>(bytes: &mut &'a mut [u8], n: usize) -> &'a mut [u8] {
    let (prefix, rest) = mem::replace(bytes, &mut []).split_at_mut(n);
    *bytes = rest;
    prefix
}

fn take_back_mut<'a>(bytes: &mut &'a mut [u8], n: usize) -> &'a mut [u8] {
    let split = <[u8]>::len(bytes) - n;
    let (rest, suffix) = mem::replace(bytes, &mut []).split_at_mut(split);
    *bytes = rest;
    suffix
}

#[cfg(test)]
mod test {
    use super::{Buf, BufferView, BufferViewMut};

    #[test]
    fn test_bufferview() {
        let v = vec![
            0x29, 0x03, 0x03, 0x01, 0x01, 0x55, 0xAA, 0x00, 0x17, 0x00, 0x0C, 0, 1, 2, 3, 3, 4, 5,
            7, 8, 9,
        ];

        let mut b = Buf::new(v.as_slice(), ..);

        assert_eq!(b.take_front(2), Some(&[0x29, 0x03][..]));
        assert_eq!(b.take_back(10), Some(&[0, 1, 2, 3, 3, 4, 5, 7, 8, 9][..]));
        assert_eq!(
            b.into_rest(),
            &[0x03, 0x01, 0x01, 0x55, 0xAA, 0x00, 0x17, 0x00, 0x0C][..]
        );
    }

    #[test]
    fn test_ref_to_slice() {
        let v = [
            0x29, 0x03, 0x03, 0x01, 0x01, 0x55, 0xAA, 0x00, 0x17, 0x00, 0x0C, 0, 1, 2, 3, 3, 4, 5,
            7, 8, 9,
        ];

        let mut b = &mut &v[..];

        assert_eq!(b.take_front(2), Some(&[0x29, 0x03][..]));
        assert_eq!(b.take_back(10), Some(&[0, 1, 2, 3, 3, 4, 5, 7, 8, 9][..]));
        assert_eq!(
            b.into_rest(),
            &[0x03, 0x01, 0x01, 0x55, 0xAA, 0x00, 0x17, 0x00, 0x0C][..]
        );
    }

    #[test]
    fn test_ref_to_mut_slice() {
        let v = [
            0x29, 0x03, 0x03, 0x01, 0x01, 0x55, 0xAA, 0x00, 0x17, 0x00, 0x0C, 0, 1, 2, 3, 3, 4, 5,
            7, 8, 9,
        ];

        let mut b = &mut &v[..];

        assert_eq!(b.take_front(2), Some(&[0x29, 0x03][..]));
        assert_eq!(b.take_back(10), Some(&[0, 1, 2, 3, 3, 4, 5, 7, 8, 9][..]));
        assert_eq!(
            b.into_rest(),
            &mut [0x03, 0x01, 0x01, 0x55, 0xAA, 0x00, 0x17, 0x00, 0x0C][..]
        );
    }

    #[test]
    fn test_mut_ref_to_mut_slice() {
        let mut v = [
            0x29, 0x03, 0x03, 0x01, 0x01, 0x55, 0xAA, 0x00, 0x17, 0x00, 0x0C, 0, 1, 2, 3, 3, 4, 5,
            7, 8, 9,
        ];

        let mut b = &mut &mut v[..];

        let f = b.take_front_zero(2).unwrap();
        f[0] = 1;
        f[1] = 2;

        let f = b.take_back_zero(2).unwrap();
        f[0] = 3;
        f[1] = 4;

        assert_eq!(b.take_front(2), Some(&[0x03, 0x01][..]));
        assert_eq!(
            b.take_back(10),
            Some(&[0, 0x0C, 0, 1, 2, 3, 3, 4, 5, 7][..])
        );
        assert_eq!(
            <&mut &mut [u8] as BufferView<&mut [u8]>>::into_rest(b),
            &mut [0x01, 0x55, 0xAA, 0x00, 0x17][..]
        );

        assert_eq!(
            v,
            &[
                0x01, 0x02, 0x03, 0x01, 0x01, 0x55, 0xAA, 0x00, 0x17, 0x00, 0x0C, 0, 1, 2, 3, 3, 4,
                5, 7, 3, 4
            ][..]
        );
    }
}
