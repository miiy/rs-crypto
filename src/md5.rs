/// MD5 hashing
///
/// https://github.com/RustCrypto/hashes/tree/master/md5
use md5::{Digest, Md5};

/// Compute the MD5 hash of a string
///
/// Example:
/// ```
/// use rs_crypto::md5;
///
/// let data = "hello";
/// let hash = md5::digest(data);
/// assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
/// ```
pub fn digest(data: &str) -> String {
    let digest = Md5::digest(data);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5() {
        let data = "hello";
        let hash = digest(data);
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
    }
}
