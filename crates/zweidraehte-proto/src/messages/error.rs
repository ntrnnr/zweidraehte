/// Results returned from parsing functions in the netstack.
pub type ParseResult<T> = core::result::Result<T, ParseError>;

/// Error type for packet parsing.
#[derive(Copy, Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ParseError {
    /// Operation is not supported.
    NotSupported,

    /// Operation is not expected in this context.
    NotExpected,

    /// Checksum is invalid.
    Checksum,

    /// Packet is not formatted properly.
    Format,

    /// Unable to parse the expected number of records.
    TooFewRecords,
}

impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::NotSupported => write!(f, "Operation is not supported"),
            Self::NotExpected => write!(f, "Operation is not expected in this context"),
            Self::Checksum => write!(f, "Invalid checksum"),
            Self::Format => write!(f, "Packet is not formatted properly"),
            Self::TooFewRecords => write!(f, "Unable to parse the expected number of records"),
        }
    }
}

impl From<core::convert::Infallible> for ParseError {
    fn from(err: core::convert::Infallible) -> ParseError {
        match err {}
    }
}
