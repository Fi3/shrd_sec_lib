//! Used to encrypt and decrypt the member's shared secret with the member password

extern crate aes;
extern crate ofb;
extern crate rand;
extern crate secrecy;
extern crate sha3;

use super::super::utils::crypto;
use secrecy::Secret;
use serde::{Deserialize, Serialize};

type Error = ofb::stream_cipher::InvalidKeyNonceLength;

/// It represent a member's encrypted shared secret with the associated username and nonce
#[derive(Debug, Serialize, Deserialize)]
pub struct GroupMember {
    pub username: String,
    encrypted_secret: Vec<u8>,
    nonce: Vec<u8>,
    pub id: usize,
}

impl GroupMember {
    /// Return a `GroupMember`. The shared_secret is passed as a mut so after the encryption the
    /// unencrypted value should no longer be in memory. TODO verify that
    ///
    /// # Arguments
    ///
    /// * `username` - String the username.
    /// * `password` - Secret containing a unencrypted binary utf8 password,
    /// * `shared_secret` - &mut Vec<u8> is a unencrypted binary utf8 secret.
    ///
    /// # Example
    /// ```
    /// use secrecy::Secret;
    /// use shrd_sec_lib::group_member::GroupMember;
    /// let member = GroupMember::new(
    ///     "user1".to_string(),
    ///     &Secret::new(b"password".to_vec()),
    ///     b"secret".to_vec(),
    ///     1,
    ///     ).unwrap();
    /// ```
    pub fn new(
        username: String,
        password: &Secret<Vec<u8>>,
        mut shared_secret: Vec<u8>,
        id: usize,
    ) -> Result<Self, Error> {
        let nonce = crypto::encrypt(password, &mut shared_secret)?;
        Ok(GroupMember {
            username,
            encrypted_secret: shared_secret,
            nonce: nonce,
            id,
        })
    }

    /// Return a `Secret` containing the member's unencrypted shared_secret.
    ///
    /// # Arguments
    ///
    /// * `password` - Secret containing a unencrypted binary utf8 password,
    ///
    /// # Example
    /// ```
    /// # use secrecy::Secret;
    /// # use secrecy::ExposeSecret;
    /// # use shrd_sec_lib::group_member::GroupMember;
    /// # let member = GroupMember::new(
    /// #     "user1".to_string(),
    /// #     &Secret::new(b"password".to_vec()),
    /// #     b"secret".to_vec(),
    /// #     1,
    /// #     ).unwrap();
    /// assert_eq!(
    ///     &b"secret".to_vec(),
    ///     member.get_secret(&Secret::new(b"password".to_vec())).unwrap().expose_secret()
    ///     );
    /// ```
    pub fn get_secret(&self, password: &Secret<Vec<u8>>) -> Result<Secret<Vec<u8>>, Error> {
        crypto::decrypt(password, &self.nonce, &self.encrypted_secret)
    }
}

#[test]
fn test_group_member_new_1() -> Result<(), Error> {
    let member = GroupMember::new(
        "user1".to_string(),
        &Secret::new(b"abcdefghilmnopqr".to_vec()),
        b"jlkahsd".to_vec(),
        1,
    )?;
    assert_eq!("user1".to_string(), member.username);
    Ok(())
}
