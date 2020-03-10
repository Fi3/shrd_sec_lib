//! Crypto utils

use rand::Rng;

use aes::Aes128;
use ofb::stream_cipher::{NewStreamCipher, SyncStreamCipher};
use ofb::Ofb;
use secrecy::ExposeSecret;
use secrecy::Secret;
use sha3::{Digest, Sha3_256};

type AesOfb = Ofb<Aes128>;
type Error = ofb::stream_cipher::InvalidKeyNonceLength;

/// Get new vector with random bytes elements.
///
/// # Arguments
///
/// * `len` - usize the vec dimension
///
/// # Example
/// ```
/// use shrd_sec_lib::utils::crypto::new_nonce;
/// assert_eq!(10, new_nonce(10).len());
/// ```
pub fn new_nonce(len: usize) -> Vec<u8> {
    let mut nonce = vec![];
    let mut rng = rand::thread_rng();
    for _ in 0..len {
        nonce.push(rng.gen());
    }
    nonce
}

/// Encryped secret and return the used nonce. The secret is encryped using AES-128-OFB as
/// stream cipher the password is hashed with SHA3-256 and truncated at 16 Bytes.
pub fn encrypt(password: &Secret<Vec<u8>>, secret: &mut Vec<u8>) -> Result<Vec<u8>, Error> {
    let nonce = new_nonce(16);
    let mut cipher = AesOfb::new_var(hash_secret(&password).expose_secret(), &nonce)?;
    cipher.apply_keystream(secret);
    Ok(nonce)
}

/// Return a Secret containing an unencrypted utf8 string. It try to decrypt the secret using
/// AES-128-OFB, the password is hashed with SHA3-256 and truncated at 16 Bytes.
pub fn decrypt(
    password: &Secret<Vec<u8>>,
    nonce: &Vec<u8>,
    encrypted_secret: &Vec<u8>,
) -> Result<Secret<Vec<u8>>, Error> {
    let mut buffer = encrypted_secret.clone();
    AesOfb::new_var(&hash_secret(password).expose_secret(), nonce)?.apply_keystream(&mut buffer);
    Ok(Secret::new(buffer))
}

pub fn hash_secret(password: &Secret<Vec<u8>>) -> Secret<Vec<u8>> {
    let mut hasher = Sha3_256::new();
    hasher.input(password.expose_secret());
    Secret::new(hasher.result()[0..16].to_vec())
}
