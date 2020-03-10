extern crate ofb;

use super::utils::crypto;
use secrecy::ExposeSecret;
use secrecy::Secret;
use serde::{Deserialize, Serialize};

type Error = ofb::stream_cipher::InvalidKeyNonceLength;

/// It represent an user branch it can generate password for the given paths
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub _username: Vec<u8>,
    encrypted_seed: Vec<u8>,
    hashed_password: Vec<u8>,
    nonce: Vec<u8>,
}

impl User {
    /// Create a new User
    pub fn new(
        _username: Vec<u8>,
        seed: &Secret<Vec<u8>>,
        password: &Secret<Vec<u8>>,
    ) -> Result<Self, Error> {
        //TODO check that username is in seed
        let mut seed = seed.expose_secret().clone();
        let nonce = crypto::encrypt(password, &mut seed)?;
        let hashed_password = crypto::hash_secret(password).expose_secret().clone();
        Ok(User {
            _username,
            encrypted_seed: seed,
            hashed_password,
            nonce,
        })
    }

    /// Decrypt the user's seed
    fn decrypt_seed(&self, password: &Secret<Vec<u8>>) -> Result<Secret<Vec<u8>>, Error> {
        assert_eq!(
            &self.hashed_password,
            crypto::hash_secret(password).expose_secret()
        );
        crypto::decrypt(password, &self.nonce, &self.encrypted_seed)
    }

    /// Get the path's password given the user password
    ///
    /// # Example
    /// ```
    /// use shrd_sec_lib::user::User;
    /// use secrecy::ExposeSecret;
    /// use secrecy::Secret;
    /// let password = Secret::new(b"super secret password".to_vec());
    /// let seed = Secret::new(b"super secret seed".to_vec());
    /// let user = User::new(b"gigi".to_vec(), & seed, & password).unwrap();
    /// assert_ne!(
    /// user.get_path(& b"path1".to_vec(), &password).unwrap().expose_secret(),
    /// user.get_path(& b"path2".to_vec(), &password).unwrap().expose_secret());
    /// ```
    pub fn get_path(
        &self,
        path: &Vec<u8>,
        password: &Secret<Vec<u8>>,
    ) -> Result<Secret<Vec<u8>>, Error> {
        let mut decrypted_seed = self.decrypt_seed(password)?.expose_secret().clone();
        for byte in path.iter() {
            decrypted_seed.push(*byte)
        }
        let decrypted_seed = Secret::new(decrypted_seed);
        Ok(crypto::hash_secret(&decrypted_seed))
    }
}
