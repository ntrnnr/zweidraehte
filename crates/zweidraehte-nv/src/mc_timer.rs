//! Independent storage for the KNX IP Secure multicast-timer watermark.
//!
//! The timer is not configuration: it must reach non-volatile storage before
//! traffic using its new value leaves the device. A device may place this
//! small store on byte-writable memory or in its own flash log.

use zweidraehte_proto::security::{SEQ6_MAX, seq6_to_u64, u64_to_seq6};

use crate::crc::crc16;
use crate::kv::{KeyValueStore, NS_MC_TIMER, SINGLETON_KEY, WearLeveledKv};
use crate::{ByteIo, SectorIo};

/// A separately selected durable home for the multicast-timer watermark.
pub trait McTimerStore {
    /// Failure from the selected medium.
    type Error;

    /// The last committed value, or `None` for a fresh or cleared store.
    /// An I/O failure remains distinct from absence.
    fn load(&self) -> Result<Option<u64>, Self::Error>;

    /// Commit a new watermark before the corresponding secure traffic leaves.
    /// Returns the medium error if that commit fails.
    fn save(&mut self, value: u64) -> Result<(), Self::Error>;

    /// Forget the value when its backbone key is erased.
    /// Returns the medium error if the clear fails.
    fn clear(&mut self) -> Result<(), Self::Error>;
}

const SLOT_LEN: u32 = 13; // magic(4), generation(1), value(6), CRC(2)

/// Two CRC-protected slots in a dedicated byte-writable region.
///
/// A write replaces the older slot, leaving the last committed one available
/// if power fails before the new slot's CRC is written.
pub struct ByteMcTimer<M: ByteIo> {
    medium: M,
    base: u32,
}

impl<M: ByteIo> ByteMcTimer<M> {
    const MAGIC: [u8; 4] = *b"KNXW";
    pub const REGION_LEN: u32 = 2 * SLOT_LEN;

    pub const fn new(medium: M, base: u32) -> Self {
        Self { medium, base }
    }

    fn slot(&self, index: u32) -> Result<Option<(u8, u64)>, M::Error> {
        let mut bytes = [0u8; SLOT_LEN as usize];
        self.medium.read_at(self.base + index * SLOT_LEN, &mut bytes)?;

        let crc = u16::from_be_bytes([bytes[11], bytes[12]]);
        if bytes[..4] != Self::MAGIC || crc16(&bytes[..11]) != crc {
            return Ok(None);
        }

        let value: [u8; 6] = bytes[5..11].try_into().expect("six watermark bytes");
        Ok(Some((bytes[4], seq6_to_u64(&value))))
    }

    fn newest(&self) -> Result<Option<(u32, u8, u64)>, M::Error> {
        let first = self.slot(0)?;
        let second = self.slot(1)?;

        Ok(match (first, second) {
            (Some((a, value)), Some((b, other))) => {
                Some(if (b.wrapping_sub(a) as i8) > 0 { (1, b, other) } else { (0, a, value) })
            }
            (Some((generation, value)), None) => Some((0, generation, value)),
            (None, Some((generation, value))) => Some((1, generation, value)),
            (None, None) => None,
        })
    }
}

impl<M: ByteIo> McTimerStore for ByteMcTimer<M> {
    type Error = M::Error;

    fn load(&self) -> Result<Option<u64>, Self::Error> {
        Ok(self.newest()?.and_then(|(_, _, value)| (value != 0).then_some(value)))
    }

    fn save(&mut self, value: u64) -> Result<(), Self::Error> {
        let (index, generation) = match self.newest()? {
            Some((current, generation, _)) => (1 - current, generation.wrapping_add(1)),
            None => (0, 0),
        };

        let mut bytes = [0u8; SLOT_LEN as usize];
        bytes[..4].copy_from_slice(&Self::MAGIC);
        bytes[4] = generation;
        bytes[5..11].copy_from_slice(&u64_to_seq6(value.min(SEQ6_MAX)));

        let at = self.base + index * SLOT_LEN;
        self.medium.write_at(at, &bytes[..11])?;
        self.medium.write_at(at + 11, &crc16(&bytes[..11]).to_be_bytes())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.save(0)
    }
}

// A one-key log lets flash boards put the watermark in their own region
// without allocating an SIAT mirror or changing the sequence log format.
impl<F: SectorIo, const ENTRIES: usize> McTimerStore for WearLeveledKv<F, ENTRIES> {
    type Error = F::Error;

    fn load(&self) -> Result<Option<u64>, Self::Error> {
        let mut bytes = [0u8; 6];
        Ok(match self.get(NS_MC_TIMER, SINGLETON_KEY, &mut bytes)? {
            Some(6) => Some(seq6_to_u64(&bytes)),
            _ => None,
        })
    }

    fn save(&mut self, value: u64) -> Result<(), Self::Error> {
        self.put(NS_MC_TIMER, SINGLETON_KEY, &u64_to_seq6(value.min(SEQ6_MAX)))
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.remove(NS_MC_TIMER, SINGLETON_KEY)
    }
}
