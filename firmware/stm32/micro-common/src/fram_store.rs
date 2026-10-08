//! FM25L16B-backed sequence numbers, SIAT, and sync-response entropy.
//!
//! The on-FRAM layout and its rules are `zweidraehte_nv::PackedSeqStore`, the
//! same code the full-stack FRAM boards and the conformance DUTs run. This
//! module only supplies the medium (a raw-PAC SPI driver for the FM25L16B) and
//! the entropy source the micro stack's `MicroSecurityResources` asks for.

use core::cell::RefCell;
use core::convert::Infallible;

use chacha20::ChaCha20Rng;
use chacha20::rand_core::TryRng;
use embedded_hal::digital::{ErrorType as DigitalErrorType, OutputPin};
use embedded_hal::spi::{ErrorType as SpiErrorType, SpiBus};
use fm25l16b::Fm25l16b;
use stm32_metapac::{self as pac, GPIOB, RCC, SPI2};
use zweidraehte_microdevice::security::MicroSecurityResources;
use zweidraehte_nv::stores::sequence::region_len;
use zweidraehte_nv::{ByteIo, PackedSeqStore};
use zweidraehte_proto::security::{SequenceNumberStorage, SiatAccess};

/// [`ByteIo`] over the FM25L16B. The driver needs `&mut` even to read, while
/// `ByteIo::read_at` takes `&self`, so the interior mutability lives here in
/// the adapter.
pub struct FramIo(RefCell<Fm25l16b<PacSpi, ChipSelect>>);

impl ByteIo for FramIo {
    type Error = ();

    fn read_at(&self, off: u32, buf: &mut [u8]) -> Result<(), ()> {
        let addr = u16::try_from(off).map_err(|_| ())?;
        self.0.borrow_mut().read(addr, buf).map_err(|_| ())
    }

    fn write_at(&mut self, off: u32, data: &[u8]) -> Result<(), ()> {
        let addr = u16::try_from(off).map_err(|_| ())?;
        self.0.get_mut().write(addr, data).map_err(|_| ())
    }
}

/// Write-through security state for a target with `SIAT` peer slots.
///
/// `FORMAT` is a product-owned four-octet on-media tag encoded as a big-endian
/// `u32`, used as the layout's magic. Giving each layout its own tag prevents
/// one firmware variant from interpreting another variant's counters.
/// Changing `SIAT` or the layout requires a new tag.
pub struct FramStore<const SIAT: usize, const FORMAT: u32> {
    store: PackedSeqStore<FramIo, SIAT>,
    rng: ChaCha20Rng,
}

impl<const SIAT: usize, const FORMAT: u32> FramStore<SIAT, FORMAT> {
    // The FM25L16B has 2 KiB. Make an oversized product declaration fail at
    // compile time instead of wrapping its 16-bit media offsets. The format
    // tag also cannot equal an erased-media pattern.
    const VALID_LAYOUT: () = {
        assert!(region_len(SIAT) <= fm25l16b::CAPACITY as usize);
        assert!(FORMAT != u32::MAX && FORMAT != 0, "an erased FRAM must not look initialized");
    };

    /// Take over SPI2 and the FRAM. The layout initialises itself on its
    /// first write, so opening touches nothing.
    pub fn open(rng: ChaCha20Rng) -> Self {
        let () = Self::VALID_LAYOUT;
        let fram = FramIo(RefCell::new(Fm25l16b::new(init_spi(), ChipSelect)));
        Self { store: PackedSeqStore::new(fram, 0, FORMAT), rng }
    }
}

// The two traits delegate to the shared store. The micro stack expects an
// out-of-range SIAT write to fail rather than be ignored, as the conformance
// DUT's adapter does too, so those bounds are checked here.

impl<const SIAT: usize, const FORMAT: u32> SequenceNumberStorage for FramStore<SIAT, FORMAT> {
    type Error = ();

    fn load_sending_seq(&self) -> Result<[u8; 6], Self::Error> {
        self.store.load_sending_seq()
    }

    fn save_sending_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.store.save_sending_seq(seq)
    }

    fn load_receiving_seq(&self, peer_ia: u16) -> Result<Option<[u8; 6]>, Self::Error> {
        self.store.load_receiving_seq(peer_ia)
    }

    fn save_receiving_seq(&mut self, peer_ia: u16, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.store.save_receiving_seq(peer_ia, seq)
    }

    fn load_tool_receiving_seq(&self) -> Result<Option<[u8; 6]>, Self::Error> {
        self.store.load_tool_receiving_seq()
    }

    fn save_tool_receiving_seq(&mut self, seq: &[u8; 6]) -> Result<(), Self::Error> {
        self.store.save_tool_receiving_seq(seq)
    }
}

impl<const SIAT: usize, const FORMAT: u32> SiatAccess for FramStore<SIAT, FORMAT> {
    type Error = ();

    fn siat_count(&self) -> u16 {
        self.store.siat_count()
    }

    fn siat_index_of(&self, ia: u16) -> Option<u16> {
        self.store.siat_index_of(ia)
    }

    fn siat_read_entry(&self, index: u16) -> Option<(u16, [u8; 6])> {
        self.store.siat_read_entry(index)
    }

    fn siat_write_entry(&mut self, index: u16, ia: u16, seq: [u8; 6]) -> Result<(), Self::Error> {
        if usize::from(index) >= SIAT {
            return Err(());
        }
        self.store.siat_write_entry(index, ia, seq)
    }

    fn siat_set_count(&mut self, count: u16) -> Result<(), Self::Error> {
        if usize::from(count) > SIAT {
            return Err(());
        }
        self.store.siat_set_count(count)
    }

    fn siat_clear(&mut self) -> Result<(), Self::Error> {
        self.store.siat_clear()
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
