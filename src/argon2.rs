/// Argon2 password hashing
///
/// https://github.com/RustCrypto/password-hashes/tree/master/argon2
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

use super::error::CryptoError;

/// Hash a password using Argon2
///
/// Example:
/// ```
/// use rs_crypto::argon2;
///
/// let password = "password";
/// let password_hash = argon2::hash_password(password).unwrap();
/// ```
pub fn hash_password(password: &str) -> Result<String, CryptoError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Verify a password against a hash
///
/// Example:
/// ```
/// use rs_crypto::argon2;
///
/// let password = "password";
/// let password_hash = "$argon2id$v=19$m=19456,t=2,p=1$oFXnXtoi6V3nXYzbeYN3/Q$vuwQ4UxZHPEmPLkkLUNiMpCoot/aWDlkb/EwlSDMvWM";
/// let result = argon2::verify_password(password, password_hash).unwrap();
/// assert_eq!(result, true);
/// ```
pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, CryptoError> {
    let argon2 = Argon2::default();
    let parsed_hash = PasswordHash::new(password_hash)?;
    Ok(argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "password";
    const PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$oFXnXtoi6V3nXYzbeYN3/Q$vuwQ4UxZHPEmPLkkLUNiMpCoot/aWDlkb/EwlSDMvWM";

    #[test]
    fn test_hash_password() {
        let password_hash = hash_password(PASSWORD).unwrap();
        println!("hash: {}", password_hash);
        assert_ne!(password_hash, PASSWORD_HASH);
    }

    #[test]
    fn test_verify_password() {
        let result = verify_password(PASSWORD, PASSWORD_HASH).unwrap();
        assert_eq!(result, true);
    }
}
