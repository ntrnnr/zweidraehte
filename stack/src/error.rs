/// Error type for an unrecognized protocol code of type `T`.
#[derive(Debug, Eq, PartialEq)]
pub struct UnrecognizedProtocolCode<T>(pub T);
