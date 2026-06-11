//! Truthlinked Axiom Src Error
//!
//! Owns typed error definitions returned by this crate.
//! VM and bytecode changes are consensus-sensitive and must remain deterministic across platforms.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxiomError {
    OutOfGas,
    CallDepthExceeded,
    InvalidOpcode(u8),
    DivisionByZero,
    ArithmeticOverflow,
    InvalidJumpTarget(u32),
    InvalidRegister(u8),
    InvalidConstIndex(u16),
    ReturnDataTooLarge,
    InvalidLength(usize),
    LogTooLarge,
    StorageReadFailed,
    StorageWriteFailed,
    Unauthorized,
    AssertFailed,
    CrossCellFailed(alloc::string::String),
    BufOverflow,
    Trap(u16),
    InvalidBytecode,
    InvalidMagic,
    NotImplemented(u8),
}

impl AxiomError {
    pub fn code(&self) -> i32 {
        match self {
            Self::OutOfGas => -100_001,
            Self::CallDepthExceeded => -100_002,
            Self::InvalidOpcode(_) => -100_003,
            Self::DivisionByZero => -100_004,
            Self::ArithmeticOverflow => -100_005,
            Self::InvalidJumpTarget(_) => -100_006,
            Self::InvalidRegister(_) => -100_007,
            Self::InvalidConstIndex(_) => -100_008,
            Self::ReturnDataTooLarge => -100_009,
            Self::InvalidLength(_) => -100_018,
            Self::LogTooLarge => -100_010,
            Self::StorageReadFailed => -100_011,
            Self::StorageWriteFailed => -100_012,
            Self::Unauthorized => -100_013,
            Self::AssertFailed => -100_014,
            Self::CrossCellFailed(_) => -100_015,
            Self::BufOverflow => -100_020,
            Self::Trap(c) => -(*c as i32),
            Self::InvalidBytecode => -100_016,
            Self::InvalidMagic => -100_017,
            Self::NotImplemented(_) => -100_019,
        }
    }
}

impl core::fmt::Display for AxiomError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}
