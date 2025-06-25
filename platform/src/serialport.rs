#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DataBits {
    Five,
    Six,
    Seven,
    Eight,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StopBits {
    One,
    Two,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Parity {
    None,
    Odd,
    Even,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub path: String,
    pub baud_rate: u32,
    pub data_bits: DataBits,
    pub stop_bits: StopBits,
    pub parity: Parity,
}
