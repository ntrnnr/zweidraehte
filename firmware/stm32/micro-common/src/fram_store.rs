//! FM25L16B-backed sequence numbers, SIAT, and sync-response entropy.

use core::cell::RefCell;
use core::convert::Infallible;

use chacha20::ChaCha20Rng;
use chacha20::rand_core::TryRng;
use embedded_hal::digital::{ErrorType as DigitalErrorType, OutputPin};
use embedded_hal::spi::{ErrorType as SpiErrorType, SpiBus};
use fm25l16b::Fm25l16b;
use stm32_metapac::{self as pac, GPIOB, RCC, SPI2};
use zweidraehte_microdevice::security::MicroSecurityResources;
use zweidraehte_proto::security::{DEFAULT_SENDING, SequenceNumberStorage, SiatAccess};

const MAGIC_OFFSET: u16 = 0;
const SENDING_OFFSET: u16 = 4;
const TOOL_OFFSET: u16 = 10;
const COUNT_OFFSET: u16 = 16;
const ENTRIES_OFFSET: u16 = 18;
const ENTRY_SIZE: u16 = 8;

/// Write-through security state for a target with `SIAT` peer slots.
///
/// `FORMAT` is a product-owned four-octet on-media tag encoded as a big-endian
/// `u32`. Giving each layout its own tag prevents one firmware variant from
/// interpreting another variant's counters. Changing `SIAT` or the layout
/// requires a new tag.
pub struct FramStore<const SIAT: usize, const FORMAT: u32> {
    fram: RefCell<Fm25l16b<PacSpi, ChipSelect>>,
    rng: ChaCha20Rng,
}

impl<const SIAT: usize, const FORMAT: u32> FramStore<SIAT, FORMAT> {
    const VALID_LAYOUT: () = {
        assert!(ENTRIES_OFFSET as usize + SIAT * ENTRY_SIZE as usize <= fm25l16b::CAPACITY as usize);
        assert!(FORMAT != u32::MAX, "an erased FRAM must not look initialized");
    };

    pub fn open(rng: ChaCha20Rng) -> Result<Self, ()> {
        // The FM25L16B has 2 KiB. Make an oversized product declaration fail
        // at compile time instead of wrapping its 16-bit media offsets. The
        // format tag also cannot equal the erased-media pattern.
        let () = Self::VALID_LAYOUT;
        let expected_magic = FORMAT.to_be_bytes();

        let mut fram = Fm25l16b::new(init_spi(), ChipSelect);
        let mut magic = [0u8; 4];
        fram.read(MAGIC_OFFSET, &mut magic).map_err(|_| ())?;
        if magic != expected_magic {
            // Publish the magic last. Interrupted initialization is retried in
            // full rather than exposing a partial replay-protection table.
            fram.write(SENDING_OFFSET, &DEFAULT_SENDING).map_err(|_| ())?;
            fram.write(TOOL_OFFSET, &[0; 6]).map_err(|_| ())?;
            fram.write(COUNT_OFFSET, &[0; 2]).map_err(|_| ())?;
            for index in 0..SIAT {
                let offset = ENTRIES_OFFSET + u16::try_from(index).map_err(|_| ())? * ENTRY_SIZE;
                fram.write(offset, &[0; ENTRY_SIZE as usize]).map_err(|_| ())?;
            }
            fram.write(MAGIC_OFFSET, &expected_magic).map_err(|_| ())?;
        }
        Ok(Self { fram: RefCell::new(fram), rng })
    }

    fn read_seq(&self, offset: u16) -> Result<[u8; 6], ()> {
        let mut seq = [0u8; 6];
        self.fram.borrow_mut().read(offset, &mut seq).map_err(|_| ())?;
        Ok(seq)
    }

    fn count(&self) -> Result<u16, ()> {
        let mut bytes = [0u8; 2];
        self.fram.borrow_mut().read(COUNT_OFFSET, &mut bytes).map_err(|_| ())?;
        let count = u16::from_be_bytes(bytes);
        (usize::from(count) <= SIAT).then_some(count).ok_or(())
    }

    fn read_entry(&self, index: u16) -> Result<(u16, [u8; 6]), ()> {
        if usize::from(index) >= SIAT {
            return Err(());
        }
        let mut bytes = [0u8; ENTRY_SIZE as usize];
        self.fram.borrow_mut().read(ENTRIES_OFFSET + index * ENTRY_SIZE, &mut bytes).map_err(|_| ())?;
        Ok((u16::from_be_bytes([bytes[0], bytes[1]]), bytes[2..].try_into().expect("six-byte SIAT sequence")))
    }

    fn write_entry(&mut self, index: u16, ia: u16, seq: [u8; 6]) -> Result<(), ()> {
        if usize::from(index) >= SIAT {
            return Err(());
        }
        let mut bytes = [0u8; ENTRY_SIZE as usize];
        bytes[..2].copy_from_slice(&ia.to_be_bytes());
        bytes[2..].copy_from_slice(&seq);
        self.fram.get_mut().write(ENTRIES_OFFSET + index * ENTRY_SIZE, &bytes).map_err(|_| ())
    }
}

impl<const SIAT: usize, const FORMAT: u32> SequenceNumberStorage for FramStore<SIAT, FORMAT> {
    type Error = ();

    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error> {
        self.read_seq(SENDING_OFFSET)
    }

    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.fram.get_mut().write(SENDING_OFFSET, seq).map_err(|_| ())
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        for index in 0..self.count()? {
            let (ia, seq) = self.read_entry(index)?;
            if ia == peer_ia {
                return Ok(Some(seq));
            }
        }
        Ok(None)
    }

    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        for index in 0..self.count()? {
            let (ia, _) = self.read_entry(index)?;
            if ia == peer_ia {
                return self.write_entry(index, ia, *seq);
            }
        }
        Err(())
    }

    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        let seq = self.read_seq(TOOL_OFFSET)?;
        Ok((seq != [0; 6]).then_some(seq))
    }

    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.fram.get_mut().write(TOOL_OFFSET, seq).map_err(|_| ())
    }
}

impl<const SIAT: usize, const FORMAT: u32> SiatAccess for FramStore<SIAT, FORMAT> {
    type Error = ();

    fn siat_count(&self) -> u16 {
        self.count().unwrap_or(0)
    }

    fn siat_index_of(&self, ia: u16) -> Option<u16> {
        (0..self.siat_count())
            .find(|&index| self.read_entry(index).is_ok_and(|entry| entry.0 == ia))
            .map(|index| index + 1)
    }

    fn siat_read_entry(&self, index: u16) -> Option<(u16, [u8; 6])> {
        (index < self.siat_count()).then(|| self.read_entry(index).ok()).flatten()
    }

    fn siat_write_entry(&mut self, index: u16, ia: u16, seq: [u8; 6]) -> Result<(), Self::Error> {
        if usize::from(index) >= SIAT {
            return Err(());
        }
        let old_count = self.count()?;
        if index >= old_count {
            for gap in old_count..index {
                self.write_entry(gap, 0, [0; 6])?;
            }
            self.write_entry(index, ia, seq)?;
            self.fram.get_mut().write(COUNT_OFFSET, &(index + 1).to_be_bytes()).map_err(|_| ())
        } else {
            self.write_entry(index, ia, seq)
        }
    }

    fn siat_set_count(&mut self, count: u16) -> Result<(), Self::Error> {
        if usize::from(count) > SIAT {
            return Err(());
        }
        let old_count = self.count()?;
        for index in count.min(old_count)..count.max(old_count) {
            self.write_entry(index, 0, [0; 6])?;
        }
        self.fram.get_mut().write(COUNT_OFFSET, &count.to_be_bytes()).map_err(|_| ())
    }

    fn siat_clear(&mut self) -> Result<(), Self::Error> {
        self.siat_set_count(0)
    }
}

impl<const SIAT: usize, const FORMAT: u32> MicroSecurityResources for FramStore<SIAT, FORMAT> {
    fn fill_random(&mut self, random: &mut [u8; 6]) {
        self.rng.try_fill_bytes(random).ok();
    }
}

pub struct PacSpi;

impl PacSpi {
    fn exchange(byte: u8) -> u8 {
        while !SPI2.sr().read().txe() {}
        SPI2.dr8().write_value(byte);
        while !SPI2.sr().read().rxne() {}
        SPI2.dr8().read()
    }
}

impl SpiErrorType for PacSpi {
    type Error = Infallible;
}

impl SpiBus<u8> for PacSpi {
    fn read(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
        for word in words {
            *word = Self::exchange(0);
        }
        Ok(())
    }

    fn write(&mut self, words: &[u8]) -> Result<(), Self::Error> {
        for &word in words {
            let _ = Self::exchange(word);
        }
        Ok(())
    }

    fn transfer(&mut self, read: &mut [u8], write: &[u8]) -> Result<(), Self::Error> {
        for index in 0..read.len().max(write.len()) {
            let received = Self::exchange(write.get(index).copied().unwrap_or(0));
            if let Some(slot) = read.get_mut(index) {
                *slot = received;
            }
        }
        Ok(())
    }

    fn transfer_in_place(&mut self, words: &mut [u8]) -> Result<(), Self::Error> {
        for word in words {
            *word = Self::exchange(*word);
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        while SPI2.sr().read().bsy() {}
        Ok(())
    }
}

pub struct ChipSelect;

impl DigitalErrorType for ChipSelect {
    type Error = Infallible;
}

impl OutputPin for ChipSelect {
    fn set_low(&mut self) -> Result<(), Self::Error> {
        GPIOB.bsrr().write(|w| w.set_br(12, true));
        Ok(())
    }

    fn set_high(&mut self) -> Result<(), Self::Error> {
        GPIOB.bsrr().write(|w| w.set_bs(12, true));
        Ok(())
    }
}

fn init_spi() -> PacSpi {
    use pac::gpio::vals::Moder;
    use pac::spi::vals::{Br, Cpha, Cpol, Ds, Frxth, Lsbfirst, Mstr};

    RCC.apbenr1().modify(|w| w.set_spi2en(true));
    GPIOB.moder().modify(|w| {
        w.set_moder(9, Moder::OUTPUT);
        w.set_moder(12, Moder::OUTPUT);
        w.set_moder(13, Moder::ALTERNATE);
        w.set_moder(14, Moder::ALTERNATE);
        w.set_moder(15, Moder::ALTERNATE);
    });
    GPIOB.afr(1).modify(|w| {
        w.set_afr(5, 0);
        w.set_afr(6, 0);
        w.set_afr(7, 0);
    });
    GPIOB.bsrr().write(|w| {
        w.set_bs(9, true);
        w.set_bs(12, true);
    });

    SPI2.cr1().write(|w| {
        w.set_cpha(Cpha::FIRST_EDGE);
        w.set_cpol(Cpol::IDLE_LOW);
        w.set_mstr(Mstr::MASTER);
        w.set_br(Br::DIV4);
        w.set_lsbfirst(Lsbfirst::MSBFIRST);
        w.set_ssi(true);
        w.set_ssm(true);
    });
    SPI2.cr2().write(|w| {
        w.set_ds(Ds::BITS8);
        w.set_frxth(Frxth::QUARTER);
    });
    SPI2.cr1().modify(|w| w.set_spe(true));
    PacSpi
}
