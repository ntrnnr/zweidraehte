//! Group object descriptor coding (03/05/01 Resources §4.10 /
//! Table 87).
//!
//! The two octets every group object table stores about an object:
//! the value field type ([`ComObjectType`], sized in
//! [`size_in_bytes`](ComObjectType::size_in_bytes) for APDU-length
//! decisions) and the configuration flags ([`ComObjectFlags`]:
//! communication/read/write/transmit/update/read-on-init enables plus
//! the transmission priority in bits 1:0).
//!
//! Pure wire coding, shared between the device stack (which serves the
//! tables) and the client's download engine (which writes them), so it
//! lives here; the device crate re-exports both types under their old
//! paths.

use crate::messages::knx::Priority;

/// Communication object data type
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ComObjectType {
    Uint1 = 0,
    Uint2 = 1,
    Uint3 = 2,
    Uint4 = 3,
    Uint5 = 4,
    Uint6 = 5,
    Uint7 = 6,
    Byte1 = 7,
    Byte2 = 8,
    Byte3 = 9,
    Byte4 = 10,
    Byte6 = 11,
    Byte8 = 12,
    Byte10 = 13,
    Byte14 = 14,
    // New data types only valid for System B
    Byte5 = 15,
    Byte7 = 16,
    Byte9 = 17,
    Byte11 = 18,
    Byte12 = 19,
    Byte13 = 20,
    Byte15 = 21,
    Byte16 = 22,
    Byte17 = 23,
    Byte18 = 24,
    Byte19 = 25,
    Byte20 = 26,
    Byte21 = 27,
    Byte22 = 28,
    Byte23 = 29,
    Byte24 = 30,
    Byte25 = 31,
    Byte26 = 32,
    Byte27 = 33,
    Byte28 = 34,
    Byte29 = 35,
    Byte30 = 36,
    Byte31 = 37,
    Byte32 = 38,
    Byte33 = 39,
    Byte34 = 40,
    Byte35 = 41,
    Byte36 = 42,
    Byte37 = 43,
    Byte38 = 44,
    Byte39 = 45,
    Byte40 = 46,
    Byte41 = 47,
    Byte42 = 48,
    Byte43 = 49,
    Byte44 = 50,
    Byte45 = 51,
    Byte46 = 52,
    Byte47 = 53,
    Byte48 = 54,
    Byte49 = 55,
    Byte50 = 56,
    Byte51 = 57,
    Byte52 = 58,
    Byte53 = 59,
    Byte54 = 60,
    Byte55 = 61,
    Byte56 = 62,
    Byte57 = 63,
    Byte58 = 64,
    Byte59 = 65,
    Byte60 = 66,
    Byte61 = 67,
    Byte62 = 68,
    Byte63 = 69,
    Byte64 = 70,
    Byte65 = 71,
    Byte66 = 72,
    Byte67 = 73,
    Byte68 = 74,
    Byte69 = 75,
    Byte70 = 76,
    Byte71 = 77,
    Byte72 = 78,
    Byte73 = 79,
    Byte74 = 80,
    Byte75 = 81,
    Byte76 = 82,
    Byte77 = 83,
    Byte78 = 84,
    Byte79 = 85,
    Byte80 = 86,
    Byte81 = 87,
    Byte82 = 88,
    Byte83 = 89,
    Byte84 = 90,
    Byte85 = 91,
    Byte86 = 92,
    Byte87 = 93,
    Byte88 = 94,
    Byte89 = 95,
    Byte90 = 96,
    Byte91 = 97,
    Byte92 = 98,
    Byte93 = 99,
    Byte94 = 100,
    Byte95 = 101,
    Byte96 = 102,
    Byte97 = 103,
    Byte98 = 104,
    Byte99 = 105,
    Byte100 = 106,
    Byte101 = 107,
    Byte102 = 108,
    Byte103 = 109,
    Byte104 = 110,
    Byte105 = 111,
    Byte106 = 112,
    Byte107 = 113,
    Byte108 = 114,
    Byte109 = 115,
    Byte110 = 116,
    Byte111 = 117,
    Byte112 = 118,
    Byte113 = 119,
    Byte114 = 120,
    Byte115 = 121,
    Byte116 = 122,
    Byte117 = 123,
    Byte118 = 124,
    Byte119 = 125,
    Byte120 = 126,
    Byte121 = 127,
    Byte122 = 128,
    Byte123 = 129,
    Byte124 = 130,
    Byte125 = 131,
    Byte126 = 132,
    Byte127 = 133,
    Byte128 = 134,
    Byte129 = 135,
    Byte130 = 136,
    Byte131 = 137,
    Byte132 = 138,
    Byte133 = 139,
    Byte134 = 140,
    Byte135 = 141,
    Byte136 = 142,
    Byte137 = 143,
    Byte138 = 144,
    Byte139 = 145,
    Byte140 = 146,
    Byte141 = 147,
    Byte142 = 148,
    Byte143 = 149,
    Byte144 = 150,
    Byte145 = 151,
    Byte146 = 152,
    Byte147 = 153,
    Byte148 = 154,
    Byte149 = 155,
    Byte150 = 156,
    Byte151 = 157,
    Byte152 = 158,
    Byte153 = 159,
    Byte154 = 160,
    Byte155 = 161,
    Byte156 = 162,
    Byte157 = 163,
    Byte158 = 164,
    Byte159 = 165,
    Byte160 = 166,
    Byte161 = 167,
    Byte162 = 168,
    Byte163 = 169,
    Byte164 = 170,
    Byte165 = 171,
    Byte166 = 172,
    Byte167 = 173,
    Byte168 = 174,
    Byte169 = 175,
    Byte170 = 176,
    Byte171 = 177,
    Byte172 = 178,
    Byte173 = 179,
    Byte174 = 180,
    Byte175 = 181,
    Byte176 = 182,
    Byte177 = 183,
    Byte178 = 184,
    Byte179 = 185,
    Byte180 = 186,
    Byte181 = 187,
    Byte182 = 188,
    Byte183 = 189,
    Byte184 = 190,
    Byte185 = 191,
    Byte186 = 192,
    Byte187 = 193,
    Byte188 = 194,
    Byte189 = 195,
    Byte190 = 196,
    Byte191 = 197,
    Byte192 = 198,
    Byte193 = 199,
    Byte194 = 200,
    Byte195 = 201,
    Byte196 = 202,
    Byte197 = 203,
    Byte198 = 204,
    Byte199 = 205,
    Byte200 = 206,
    Byte201 = 207,
    Byte202 = 208,
    Byte203 = 209,
    Byte204 = 210,
    Byte205 = 211,
    Byte206 = 212,
    Byte207 = 213,
    Byte208 = 214,
    Byte209 = 215,
    Byte210 = 216,
    Byte211 = 217,
    Byte212 = 218,
    Byte213 = 219,
    Byte214 = 220,
    Byte215 = 221,
    Byte216 = 222,
    Byte217 = 223,
    Byte218 = 224,
    Byte219 = 225,
    Byte220 = 226,
    Byte221 = 227,
    Byte222 = 228,
    Byte223 = 229,
    Byte224 = 230,
    Byte225 = 231,
    Byte226 = 232,
    Byte227 = 233,
    Byte228 = 234,
    Byte229 = 235,
    Byte230 = 236,
    Byte231 = 237,
    Byte232 = 238,
    Byte233 = 239,
    Byte234 = 240,
    Byte235 = 241,
    Byte236 = 242,
    Byte237 = 243,
    Byte238 = 244,
    Byte239 = 245,
    Byte240 = 246,
    Byte241 = 247,
    Byte242 = 248,
    Byte243 = 249,
    Byte244 = 250,
    Byte245 = 251,
    Byte246 = 252,
    Byte247 = 253,
    Byte248 = 254,
    Byte252 = 255,
}

impl From<u8> for ComObjectType {
    fn from(value: u8) -> Self {
        // SAFETY: `ComObjectType` is `#[repr(u8)]` and covers all 256 discriminants
        // (0-254 are named variants; 255 is `Byte252`). Every `u8` is therefore a
        // valid discriminant. The round-trip test below (`test_com_object_type_roundtrip`)
        // iterates all 256 values and verifies that `u8::from(ComObjectType::from(v)) == v`,
        // which catches any future gap if a variant is removed.
        unsafe { core::mem::transmute(value) }
    }
}

impl From<ComObjectType> for u8 {
    fn from(value: ComObjectType) -> Self {
        value as u8
    }
}

impl ComObjectType {
    /// Get the size in bytes for this object type and whether it's a compact type
    /// that fits in the 6 APCI bits for short APDUs.
    ///
    /// Returns `(size_in_bytes, is_short_format)` where:
    /// - `size_in_bytes` is the number of bytes the value occupies
    /// - `is_short_format` is true if the value can fit in the 6-bit APCI data field
    pub fn size_in_bytes(&self) -> (usize, bool) {
        match *self {
            // Uint types (0-6): All are 1 byte, but only Uint1-Uint6 fit in short format
            Self::Uint1 | Self::Uint2 | Self::Uint3 | Self::Uint4 | Self::Uint5 | Self::Uint6 => (1, true),
            Self::Uint7 | Self::Byte1 => (1, false),
            Self::Byte2 => (2, false),
            Self::Byte3 => (3, false),
            Self::Byte4 => (4, false),
            Self::Byte5 => (5, false),
            Self::Byte6 => (6, false),
            Self::Byte7 => (7, false),
            Self::Byte8 => (8, false),
            Self::Byte9 => (9, false),
            Self::Byte10 => (10, false),
            Self::Byte11 => (11, false),
            Self::Byte12 => (12, false),
            Self::Byte13 => (13, false),
            Self::Byte14 => (14, false),
            Self::Byte15 => (15, false),
            Self::Byte252 => (252, false),
            // For Byte16-Byte248, the value is (enum_value - 6)
            _ => {
                let i: u8 = (*self).into();
                ((i as usize) - 6, false)
            }
        }
    }

    /// Parse an ETS `ObjectSize` string — `"1 Bit"` … `"7 Bit"`,
    /// `"1 Byte"`, `"2 Bytes"` … — into the type it names.
    ///
    /// This is the coding a `.knxprod` / MTXML `ComObject/@ObjectSize`
    /// carries; a management client writing the group object table
    /// needs the type code it maps to. Derived from
    /// [`size_in_bytes`](Self::size_in_bytes) rather than a second
    /// table, so the two cannot drift: a `"Bit"` size is a `Uint`
    /// (the sub-byte codes 0–6), a `"Byte(s)"` size is the lowest
    /// `Byte*` code of that width. `None` for a string this coding
    /// does not define, so a caller can reject an unknown size instead
    /// of silently substituting one.
    pub fn from_ets_size_string(s: &str) -> Option<Self> {
        let (count, unit) = s.trim().split_once(' ')?;
        let count: u16 = count.parse().ok()?;

        match unit {
            "Bit" | "Bits" => {
                // Uint1..Uint7 are codes 0..6.
                (1..=7).contains(&count).then(|| Self::from((count - 1) as u8))
            }
            "Byte" | "Bytes" => {
                // The Byte* variants start at code 7; find the one of
                // this width (there is exactly one per byte count).
                (7u8..=255).map(Self::from).find(|t| t.size_in_bytes().0 == count as usize)
            }
            _ => None,
        }
    }
}

/// A Communication object flags field.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(transparent)]
pub struct ComObjectFlags(u8);

impl ComObjectFlags {
    pub const UE_FLAG_MASK: u8 = 0b10000000; // Update Enable flag
    pub const TE_FLAG_MASK: u8 = 0b01000000; // Transmission Enable flag
    pub const ROI_FLAG_MASK: u8 = 0b00100000; // Read on Init flag
    pub const WE_FLAG_MASK: u8 = 0b00010000; // Write Enable flag
    pub const RE_FLAG_MASK: u8 = 0b00001000; // Read Enable flag
    pub const CE_FLAG_MASK: u8 = 0b00000100; // Communication Enable flag

    const P_SHIFT: u8 = 0;
    const P_LEN: u8 = 2;
    const P_MAX: u8 = (1 << Self::P_LEN) - 1; // Max priority value (3)
    const P_MASK: u8 = Self::P_MAX << Self::P_SHIFT;

    /// Common group object configuration: Transmit to bus (T)
    pub const CONFIG_T: u8 = Self::CE_FLAG_MASK | Self::TE_FLAG_MASK;

    /// Common group object configuration: Transmit to bus, read from bus (RT)
    pub const CONFIG_RT: u8 = Self::CE_FLAG_MASK | Self::TE_FLAG_MASK | Self::RE_FLAG_MASK;

    /// Common group object configuration: Receive from bus (WU)
    pub const CONFIG_WU: u8 = Self::CE_FLAG_MASK | Self::WE_FLAG_MASK | Self::UE_FLAG_MASK;

    /// Common group object configuration: Transmit to bus, receive, read from bus (RTWU)
    pub const CONFIG_RTWU: u8 =
        Self::CE_FLAG_MASK | Self::TE_FLAG_MASK | Self::WE_FLAG_MASK | Self::UE_FLAG_MASK | Self::RE_FLAG_MASK;
}

impl Default for ComObjectFlags {
    fn default() -> Self {
        // Default to CONFIG_RTWU - full communication capability
        Self(Self::CONFIG_RTWU | u8::from(Priority::Low))
    }
}

impl ComObjectFlags {
    /// Create ComObjectFlags from a raw byte value.
    #[inline]
    pub const fn from_byte(value: u8) -> Self {
        Self(value)
    }

    /// Get the raw byte value of the flags.
    #[inline]
    pub const fn to_byte(self) -> u8 {
        self.0
    }

    #[inline]
    pub fn transmission_enable(&self) -> bool {
        self.0 & Self::TE_FLAG_MASK != 0
    }

    #[inline]
    pub fn read_on_init(&self) -> bool {
        self.0 & Self::ROI_FLAG_MASK != 0
    }

    #[inline]
    pub fn write_enable(&self) -> bool {
        self.0 & Self::WE_FLAG_MASK != 0
    }

    #[inline]
    pub fn read_enable(&self) -> bool {
        self.0 & Self::RE_FLAG_MASK != 0
    }

    #[inline]
    pub fn update_enable(&self) -> bool {
        self.0 & Self::UE_FLAG_MASK != 0
    }

    #[inline]
    pub fn communication_enable(&self) -> bool {
        self.0 & Self::CE_FLAG_MASK != 0
    }

    #[inline]
    pub fn priority(&self) -> Priority {
        let p = (self.0 & Self::P_MASK) >> Self::P_SHIFT;
        Priority::from(p)
    }

    /// Check if flags contain a specific flag pattern
    #[inline]
    pub fn contains(&self, flag: u8) -> bool {
        (self.0 & flag) == flag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that every `u8` value round-trips through `ComObjectType::from` and
    /// back to `u8`.  This test is the safety guard for the `transmute` in
    /// `From<u8> for ComObjectType`: if a variant is ever removed, the gap will
    /// cause this test to fail rather than silently producing undefined behaviour at
    /// runtime.
    #[test]
    fn test_com_object_type_roundtrip() {
        for v in 0u8..=255 {
            let cot = ComObjectType::from(v);
            let back: u8 = cot.into();
            assert_eq!(back, v, "ComObjectType round-trip failed for value {v}");
        }
    }

    #[test]
    fn ets_size_strings_parse_to_the_right_type() {
        assert_eq!(ComObjectType::from_ets_size_string("1 Bit"), Some(ComObjectType::Uint1));
        assert_eq!(ComObjectType::from_ets_size_string("4 Bit"), Some(ComObjectType::Uint4));
        assert_eq!(ComObjectType::from_ets_size_string("7 Bit"), Some(ComObjectType::Uint7));
        // A "Byte" size is the Byte* variant of that width, not Uint7.
        assert_eq!(ComObjectType::from_ets_size_string("1 Byte"), Some(ComObjectType::Byte1));
        assert_eq!(ComObjectType::from_ets_size_string("2 Bytes"), Some(ComObjectType::Byte2));
        assert_eq!(ComObjectType::from_ets_size_string("14 Bytes"), Some(ComObjectType::Byte14));
        // The BCU1 ordering is not monotonic in code, but width still
        // resolves uniquely (Byte5 is code 15, after Byte14).
        assert_eq!(ComObjectType::from_ets_size_string("5 Bytes"), Some(ComObjectType::Byte5));
        assert_eq!(u8::from(ComObjectType::from_ets_size_string("5 Bytes").unwrap()), 15);

        assert_eq!(ComObjectType::from_ets_size_string("8 Bit"), None, "8 bits is a byte, not a Uint");
        assert_eq!(ComObjectType::from_ets_size_string("nonsense"), None);
        assert_eq!(ComObjectType::from_ets_size_string("3 Widgets"), None);
    }
}
