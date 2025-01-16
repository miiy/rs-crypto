/// AES ECB mode encryption and decryption
///
/// https://github.com/magic-akari/ecb
use super::error::CryptoError;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyInit, BlockSizeUser};

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;
type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;

/// Encrypt plain text using AES ECB mode
///
/// Example:
/// ```
/// use rs_crypto::aes_ecb;
///
/// let plain_text = "hello";
/// let key = [0u8; 16];
/// let cipher_text = aes_ecb::encrypt(plain_text, key).unwrap();
/// let hex_cipher_text = hex::encode(cipher_text);
/// assert_eq!(hex_cipher_text, "9834ed518cbc8fbe9af3c6ecb75eb8c0");
/// ```
pub fn encrypt(plain_text: &str, key: [u8; 16]) -> Result<Vec<u8>, CryptoError> {
    let pt_len = plain_text.len();
    let block_size = Aes128EcbEnc::block_size();
    let padding_size = (block_size - (pt_len % block_size)) % block_size;

    let buf_len = pt_len + padding_size;
    let mut buf = vec![0u8; buf_len];
    buf[..pt_len].copy_from_slice(&plain_text.as_bytes());

    let ct = Aes128EcbEnc::new(&key.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
        .map_err(|_| CryptoError::PadError)?;

    Ok(ct.to_vec())
}

/// Decrypt cipher text using AES ECB mode
///
/// Example:
/// ```
/// use hex;
/// use rs_crypto::aes_ecb;
///
/// let cipher_text = hex::decode("9834ed518cbc8fbe9af3c6ecb75eb8c0").unwrap();
/// let key = [0u8; 16];
/// let plain_text = aes_ecb::decrypt(cipher_text, key).unwrap();
/// let plain_text_str = String::from_utf8(plain_text).unwrap();
/// assert_eq!(plain_text_str, "hello");
/// ```
pub fn decrypt(cipher_text: Vec<u8>, key: [u8; 16]) -> Result<Vec<u8>, CryptoError> {
    let mut buf = cipher_text;

    let pt = Aes128EcbDec::new(&key.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| CryptoError::UnpadError)?;
    Ok(pt.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [0u8; 16];
    const PLAIN_TEXT: &str = "hello";
    const CIPHER_TEXT: &str = "9834ed518cbc8fbe9af3c6ecb75eb8c0";

    #[test]
    fn test_aes_ecb_encrypt() {
        let cipher_text = encrypt(PLAIN_TEXT, KEY).unwrap();
        let hex_cipher_text = hex::encode(cipher_text);
        println!("{:?}", hex_cipher_text);
        assert_eq!(hex_cipher_text, CIPHER_TEXT);
    }

    #[test]
    fn test_aes_ecb_decrypt() {
        let cipher_text = hex::decode(CIPHER_TEXT).unwrap();
        let plain_text = decrypt(cipher_text.into(), KEY).unwrap();
        let plain_text_str = String::from_utf8(plain_text).unwrap();
        println!("plain_text: {}", plain_text_str);
        assert_eq!(PLAIN_TEXT, plain_text_str);
    }

    #[test]
    fn test_aes_ecb_round_trip() {
        let cipher_text = encrypt(PLAIN_TEXT, KEY).unwrap();
        let decrypted = decrypt(cipher_text, KEY).unwrap();

        assert_eq!(PLAIN_TEXT.as_bytes(), decrypted.as_slice());
    }
}
