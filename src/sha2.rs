/// SHA256 hashing
///
/// https://github.com/RustCrypto/hashes/tree/master/sha2
use sha2::{Digest, Sha256};

/// Compute the SHA256 hash of a string
///
/// Example:
/// ```
/// use rs_crypto::sha2;
///
/// let data = "hello";
/// let hash = sha2::sha256_digest(data);
/// assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
/// ```
pub fn sha256_digest(data: &str) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let data = "hello";
        let hash = sha256_digest(data);
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }
}
