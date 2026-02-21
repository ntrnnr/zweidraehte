//! TCP framing for KNX/IP.
//!
//! TCP is stream-oriented: there is no 1:1 relation between TCP segments
//! and KNX/IP frames. One TCP segment may contain multiple frames, and one
//! frame may span multiple segments. This module recovers frame boundaries
//! from the byte stream using the 6-byte KNX/IP header.
//!
//! Per KNX spec 3/8/2 §8.4.3.3:
//! - Senders send frames back-to-back without extra octets.
//! - Receivers use the header to recover frame structure.
//! - Bad header → close TCP connection.
//! - Frame too large for buffer → skip the body, don't close.
//! - Unknown service type → still valid structurally, don't close.
//!
//! The [`KnxIpFrameReader`] is a synchronous push-based state machine.
//! It consumes raw bytes via [`feed()`](KnxIpFrameReader::feed) and
//! produces [`FrameEvent`]s. No async, no allocations — testable
//! without an executor and usable in no_std.

/// Size of the KNX/IP header (header_size + version + service_type + total_length).
const KNXIP_HEADER_SIZE: usize = 6;

/// Expected value of the `header_size` field.
const EXPECTED_HEADER_SIZE: u8 = 0x06;

/// Expected value of the `version` field (protocol version 1.0).
const EXPECTED_VERSION: u8 = 0x10;

/// Result of feeding bytes into the frame reader.
pub enum FrameEvent {
    /// A complete KNX/IP frame has been written into the output buffer.
    /// The value is the total frame length (including the 6-byte header).
    Frame(usize),

    /// The reader needs more bytes before it can produce a frame.
    NeedMoreData,

    /// An oversized frame was skipped (body larger than the output buffer).
    /// The reader has consumed and discarded the frame's bytes without
    /// storing them. This is not a fatal error per spec.
    FrameSkipped {
        /// The total_length from the frame's header.
        total_length: u16,
    },

    /// The header is malformed (bad header_size, bad version, or
    /// total_length < 6). The caller MUST close the TCP connection.
    ProtocolError,
}

/// Internal state of the frame reader.
enum State {
    /// Accumulating the 6-byte KNX/IP header.
    ReadingHeader,
    /// Reading the frame body into the output buffer.
    ReadingBody,
    /// Skipping an oversized frame body (not stored, just consumed).
    SkippingBody,
}

/// State machine for extracting KNX/IP frames from a TCP byte stream.
///
/// # Usage
///
/// ```ignore
/// let mut reader = KnxIpFrameReader::new();
/// let mut output = [0u8; 512];
///
/// loop {
///     // Read raw bytes from the TCP stream into `input`.
///     let n = stream.read(&mut input).await?;
///     let mut pos = 0;
///     while pos < n {
///         let (consumed, event) = reader.feed(&input[pos..], &mut output);
///         pos += consumed;
///         match event {
///             FrameEvent::Frame(len) => handle_frame(&output[..len]),
///             FrameEvent::NeedMoreData => break,
///             FrameEvent::FrameSkipped { .. } => { /* logged internally */ },
///             FrameEvent::ProtocolError => { close_connection(); return; },
///         }
///     }
/// }
/// ```
pub struct KnxIpFrameReader {
    state: State,
    /// Partial header accumulator.
    header_buf: [u8; KNXIP_HEADER_SIZE],
    /// How many header bytes have been accumulated.
    header_len: usize,
    /// Total frame length from the parsed header (set after header is complete).
    frame_total_length: u16,
    /// How many body bytes have been consumed so far (reading or skipping).
    body_progress: usize,
}

impl KnxIpFrameReader {
    /// Create a new frame reader in the initial state.
    pub const fn new() -> Self {
        Self {
            state: State::ReadingHeader,
            header_buf: [0; KNXIP_HEADER_SIZE],
            header_len: 0,
            frame_total_length: 0,
            body_progress: 0,
        }
    }

    /// Feed input bytes and optionally produce a frame event.
    ///
    /// Returns `(consumed, event)` where `consumed` is the number of bytes
    /// consumed from `input`. The caller should advance its read position
    /// by this amount. If `FrameEvent::Frame(len)` is returned, the
    /// complete frame (including header) is in `output[..len]`.
    ///
    /// Call repeatedly with the same input (advancing by `consumed` each
    /// time) until `FrameEvent::NeedMoreData` is returned.
    pub fn feed(&mut self, input: &[u8], output: &mut [u8]) -> (usize, FrameEvent) {
        if input.is_empty() {
            return (0, FrameEvent::NeedMoreData);
        }

        match self.state {
            State::ReadingHeader => self.feed_header(input, output),
            State::ReadingBody => self.feed_body(input, output),
            State::SkippingBody => self.feed_skip(input),
        }
    }

    /// Accumulate header bytes. When we have all 6, validate and transition.
    fn feed_header(&mut self, input: &[u8], output: &mut [u8]) -> (usize, FrameEvent) {
        let need = KNXIP_HEADER_SIZE - self.header_len;
        let available = input.len().min(need);

        self.header_buf[self.header_len..self.header_len + available]
            .copy_from_slice(&input[..available]);
        self.header_len += available;

        if self.header_len < KNXIP_HEADER_SIZE {
            return (available, FrameEvent::NeedMoreData);
        }

        // Header is complete — validate it.
        let header_size = self.header_buf[0];
        let version = self.header_buf[1];
        let total_length = u16::from_be_bytes([self.header_buf[4], self.header_buf[5]]);

        if header_size != EXPECTED_HEADER_SIZE || version != EXPECTED_VERSION {
            self.reset();
            return (available, FrameEvent::ProtocolError);
        }

        if (total_length as usize) < KNXIP_HEADER_SIZE {
            self.reset();
            return (available, FrameEvent::ProtocolError);
        }

        self.frame_total_length = total_length;
        let body_len = total_length as usize - KNXIP_HEADER_SIZE;

        if total_length as usize > output.len() {
            // Frame is too large for the output buffer — skip it.
            if body_len == 0 {
                // Header-only frame that's too large (shouldn't happen
                // with a 6-byte minimum, but handle it).
                self.reset();
                return (available, FrameEvent::FrameSkipped { total_length });
            }
            self.body_progress = 0;
            self.state = State::SkippingBody;
            return (available, FrameEvent::NeedMoreData);
        }

        // Copy header into output buffer.
        output[..KNXIP_HEADER_SIZE].copy_from_slice(&self.header_buf);

        if body_len == 0 {
            // No body — frame is complete (just the 6-byte header).
            self.reset();
            return (available, FrameEvent::Frame(KNXIP_HEADER_SIZE));
        }

        self.body_progress = 0;
        self.state = State::ReadingBody;

        // Try to consume body bytes from remaining input.
        let remaining = &input[available..];
        if remaining.is_empty() {
            return (available, FrameEvent::NeedMoreData);
        }

        let (body_consumed, event) = self.feed_body(remaining, output);
        (available + body_consumed, event)
    }

    /// Read body bytes into the output buffer.
    fn feed_body(&mut self, input: &[u8], output: &mut [u8]) -> (usize, FrameEvent) {
        let body_len = self.frame_total_length as usize - KNXIP_HEADER_SIZE;
        let remaining_body = body_len - self.body_progress;
        let available = input.len().min(remaining_body);

        let dst_start = KNXIP_HEADER_SIZE + self.body_progress;
        output[dst_start..dst_start + available].copy_from_slice(&input[..available]);
        self.body_progress += available;

        if self.body_progress >= body_len {
            let total = self.frame_total_length as usize;
            self.reset();
            (available, FrameEvent::Frame(total))
        } else {
            (available, FrameEvent::NeedMoreData)
        }
    }

    /// Skip body bytes for an oversized frame (consume without storing).
    fn feed_skip(&mut self, input: &[u8]) -> (usize, FrameEvent) {
        let body_len = self.frame_total_length as usize - KNXIP_HEADER_SIZE;
        let remaining_body = body_len - self.body_progress;
        let available = input.len().min(remaining_body);
        self.body_progress += available;

        if self.body_progress >= body_len {
            let total_length = self.frame_total_length;
            self.reset();
            (available, FrameEvent::FrameSkipped { total_length })
        } else {
            (available, FrameEvent::NeedMoreData)
        }
    }

    /// Reset to initial state for the next frame.
    fn reset(&mut self) {
        self.state = State::ReadingHeader;
        self.header_len = 0;
        self.frame_total_length = 0;
        self.body_progress = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid KNX/IP frame with the given service type and body.
    fn make_frame(service_type: u16, body: &[u8]) -> Vec<u8> {
        let total_len = (KNXIP_HEADER_SIZE + body.len()) as u16;
        let mut frame = Vec::new();
        frame.push(EXPECTED_HEADER_SIZE);
        frame.push(EXPECTED_VERSION);
        frame.extend_from_slice(&service_type.to_be_bytes());
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(body);
        frame
    }

    #[test]
    fn single_complete_frame() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        let frame = make_frame(0x0201, &[1, 2, 3, 4]);

        let (consumed, event) = reader.feed(&frame, &mut output);
        assert_eq!(consumed, frame.len());
        assert!(matches!(event, FrameEvent::Frame(len) if len == frame.len()));
        assert_eq!(&output[..frame.len()], &frame[..]);
    }

    #[test]
    fn header_split_across_two_feeds() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        let frame = make_frame(0x0201, &[10, 20]);

        // Feed first 3 bytes of header
        let (consumed, event) = reader.feed(&frame[..3], &mut output);
        assert_eq!(consumed, 3);
        assert!(matches!(event, FrameEvent::NeedMoreData));

        // Feed remaining bytes
        let (consumed, event) = reader.feed(&frame[3..], &mut output);
        assert_eq!(consumed, frame.len() - 3);
        assert!(matches!(event, FrameEvent::Frame(len) if len == frame.len()));
        assert_eq!(&output[..frame.len()], &frame[..]);
    }

    #[test]
    fn body_split_across_feeds() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        let body = [1, 2, 3, 4, 5, 6, 7, 8];
        let frame = make_frame(0x0310, &body);

        // Feed header + 2 bytes of body
        let split = KNXIP_HEADER_SIZE + 2;
        let (consumed, event) = reader.feed(&frame[..split], &mut output);
        assert_eq!(consumed, split);
        assert!(matches!(event, FrameEvent::NeedMoreData));

        // Feed remaining body
        let (consumed, event) = reader.feed(&frame[split..], &mut output);
        assert_eq!(consumed, frame.len() - split);
        assert!(matches!(event, FrameEvent::Frame(len) if len == frame.len()));
        assert_eq!(&output[..frame.len()], &frame[..]);
    }

    #[test]
    fn two_frames_back_to_back() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        let frame1 = make_frame(0x0201, &[1, 2]);
        let frame2 = make_frame(0x0202, &[3, 4, 5]);

        let mut combined = Vec::new();
        combined.extend_from_slice(&frame1);
        combined.extend_from_slice(&frame2);

        // First feed should produce frame1
        let (consumed1, event) = reader.feed(&combined, &mut output);
        assert_eq!(consumed1, frame1.len());
        assert!(matches!(event, FrameEvent::Frame(len) if len == frame1.len()));
        assert_eq!(&output[..frame1.len()], &frame1[..]);

        // Second feed (remaining bytes) should produce frame2
        let (consumed2, event) = reader.feed(&combined[consumed1..], &mut output);
        assert_eq!(consumed2, frame2.len());
        assert!(matches!(event, FrameEvent::Frame(len) if len == frame2.len()));
        assert_eq!(&output[..frame2.len()], &frame2[..]);
    }

    #[test]
    fn oversized_frame_skipped() {
        let mut reader = KnxIpFrameReader::new();
        // Output buffer is only 20 bytes
        let mut output = [0u8; 20];
        // Frame with 100 bytes of body — total 106, exceeds output
        let body = vec![0xAA; 100];
        let frame = make_frame(0x0999, &body);

        // Feed all at once
        let mut pos = 0;
        let mut skipped = false;
        while pos < frame.len() {
            let (consumed, event) = reader.feed(&frame[pos..], &mut output);
            pos += consumed;
            match event {
                FrameEvent::FrameSkipped { total_length } => {
                    assert_eq!(total_length, 106);
                    skipped = true;
                    break;
                }
                FrameEvent::NeedMoreData => continue,
                _ => panic!("unexpected event"),
            }
        }
        assert!(skipped);
        assert_eq!(pos, frame.len());
    }

    #[test]
    fn bad_header_size_is_protocol_error() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        // header_size = 0x07 instead of 0x06
        let input = [0x07, 0x10, 0x02, 0x01, 0x00, 0x08, 0x00, 0x00];

        let (consumed, event) = reader.feed(&input, &mut output);
        assert_eq!(consumed, 6); // consumed the 6 header bytes
        assert!(matches!(event, FrameEvent::ProtocolError));
    }

    #[test]
    fn bad_version_is_protocol_error() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        // version = 0x20 instead of 0x10
        let input = [0x06, 0x20, 0x02, 0x01, 0x00, 0x08, 0x00, 0x00];

        let (consumed, event) = reader.feed(&input, &mut output);
        assert_eq!(consumed, 6);
        assert!(matches!(event, FrameEvent::ProtocolError));
    }

    #[test]
    fn total_length_too_small_is_protocol_error() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        // total_length = 5, less than the 6-byte header minimum
        let input = [0x06, 0x10, 0x02, 0x01, 0x00, 0x05];

        let (consumed, event) = reader.feed(&input, &mut output);
        assert_eq!(consumed, 6);
        assert!(matches!(event, FrameEvent::ProtocolError));
    }

    #[test]
    fn empty_input_returns_need_more_data() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        let (consumed, event) = reader.feed(&[], &mut output);
        assert_eq!(consumed, 0);
        assert!(matches!(event, FrameEvent::NeedMoreData));
    }

    #[test]
    fn header_only_frame() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        // total_length = 6, no body
        let input = [0x06, 0x10, 0x02, 0x01, 0x00, 0x06];

        let (consumed, event) = reader.feed(&input, &mut output);
        assert_eq!(consumed, 6);
        assert!(matches!(event, FrameEvent::Frame(6)));
        assert_eq!(&output[..6], &input[..]);
    }

    #[test]
    fn byte_at_a_time() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];
        let frame = make_frame(0x0205, &[10, 20, 30]);

        for (i, byte) in frame.iter().enumerate() {
            let (consumed, event) = reader.feed(core::slice::from_ref(byte), &mut output);
            assert_eq!(consumed, 1);
            if i < frame.len() - 1 {
                assert!(matches!(event, FrameEvent::NeedMoreData));
            } else {
                assert!(matches!(event, FrameEvent::Frame(len) if len == frame.len()));
            }
        }
        assert_eq!(&output[..frame.len()], &frame[..]);
    }

    #[test]
    fn recovery_after_protocol_error() {
        // After a ProtocolError the reader resets, so the next feed
        // starts fresh (though in practice the caller closes the TCP
        // connection). Verify that reset works correctly.
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 512];

        // Bad header
        let bad = [0x06, 0x20, 0x02, 0x01, 0x00, 0x08, 0x00, 0x00];
        let (_, event) = reader.feed(&bad, &mut output);
        assert!(matches!(event, FrameEvent::ProtocolError));

        // Now feed a good frame — reader should have reset
        let frame = make_frame(0x0201, &[42]);
        let (consumed, event) = reader.feed(&frame, &mut output);
        assert_eq!(consumed, frame.len());
        assert!(matches!(event, FrameEvent::Frame(len) if len == frame.len()));
    }

    #[test]
    fn skip_then_normal_frame() {
        let mut reader = KnxIpFrameReader::new();
        let mut output = [0u8; 20]; // small buffer

        // Build oversized + normal frames back to back
        let big_body = vec![0xBB; 50];
        let big_frame = make_frame(0x0999, &big_body);
        let small_frame = make_frame(0x0201, &[1, 2]);
        let mut combined = Vec::new();
        combined.extend_from_slice(&big_frame);
        combined.extend_from_slice(&small_frame);

        let mut pos = 0;
        let mut events = Vec::new();

        while pos < combined.len() {
            let (consumed, event) = reader.feed(&combined[pos..], &mut output);
            if consumed == 0 {
                break;
            }
            pos += consumed;
            match &event {
                FrameEvent::NeedMoreData => {}
                _ => events.push(event),
            }
        }

        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], FrameEvent::FrameSkipped { total_length: 56 }));
        assert!(matches!(events[1], FrameEvent::Frame(8)));
    }
}
