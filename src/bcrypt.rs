/// Bcrypt password hashing
///
/// https://github.com/Keats/rust-bcrypt
use super::error::CryptoError;

pub type Cost = u32;
pub const DEFAULT_COST: Cost = 10;

/// Hash a password using Bcrypt
///
/// Example:
/// ```
/// use rs_crypto::bcrypt;
/// let password = "password";
/// let password_hash = bcrypt::hash(password, bcrypt::DEFAULT_COST).unwrap();
/// ```
pub fn hash(password: &str, cost: Cost) -> Result<String, CryptoError> {
    Ok(bcrypt::hash(password, cost)?)
}

/// Verify a password against a hash
///
/// Example:
/// ```
/// use rs_crypto::bcrypt;
///
/// let password = "password";
/// let hash = "$2b$10$jmi9fwZp.w4OKoTMekPWHu48myFExfX85sUGmXVABsS0tNNn3pjkO";
/// let result = bcrypt::verify(password, hash).unwrap();
/// ```
pub fn verify(password: &str, hash: &str) -> Result<bool, CryptoError> {
    Ok(bcrypt::verify(password, hash)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "password";
    const HASH: &str = "$2b$10$jmi9fwZp.w4OKoTMekPWHu48myFExfX85sUGmXVABsS0tNNn3pjkO";

    #[test]
    fn test_bcrypt_hash() {
        let password_hash = hash(PASSWORD, DEFAULT_COST).unwrap();
        println!("password_hash: {}", password_hash);
        assert_ne!(password_hash, HASH);
    }

    #[test]
    fn test_bcrypt_verify() {
        let result = verify(PASSWORD, HASH).unwrap();
        assert_eq!(result, true);
    }
}
