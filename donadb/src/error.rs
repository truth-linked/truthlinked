//! Error types shared by the DonaDB public API.

use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
/// Recoverable errors returned by DonaDB operations.
pub enum DbError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid argument: {0}")]
    Invalid(String),
}

/// Convenient result alias for DonaDB operations.
pub type DbResult<T> = Result<T, DbError>;
