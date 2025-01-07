use argon2::password_hash;
use bcrypt::BcryptError;
use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    PadError,

    UnpadError,

    Argon2Error { source: password_hash::Error },

    BcryptError { source: BcryptError },
}

impl From<BcryptError> for CryptoError {
    fn from(source: BcryptError) -> Self {
        Self::BcryptError { source }
    }
}

impl From<password_hash::Error> for CryptoError {
    fn from(source: password_hash::Error) -> Self {
        Self::Argon2Error { source }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Argon2Error { source } => write!(f, "Argon2 error: {}", source),
            Self::BcryptError { source } => write!(f, "Bcrypt error: {}", source),
            Self::PadError => write!(f, "Pad error"),
            Self::UnpadError => write!(f, "Unpad error"),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Argon2Error { source } => Some(source),
            Self::BcryptError { source } => Some(source),
            _ => None,
        }
    }
}
