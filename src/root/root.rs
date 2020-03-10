use super::super::utils::crypto;
use super::group_member::GroupMember;
use ofb;
use secrecy::ExposeSecret;
use secrecy::Secret;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use threshold_crypto::serde_impl::SerdeSecret;
use threshold_crypto::{Ciphertext, PublicKeySet, SecretKeyShare};

type InvalidKNLen = ofb::stream_cipher::InvalidKeyNonceLength;

#[derive(Debug)]
pub enum Error {
    InvalidKeyNonceLength(InvalidKNLen),
    InvalidUser,
    ThresholdError,
    None,
}

impl From<InvalidKNLen> for Error {
    fn from(error: InvalidKNLen) -> Self {
        Error::InvalidKeyNonceLength(error)
    }
}

impl From<std::option::NoneError> for Error {
    fn from(_: std::option::NoneError) -> Self {
        Error::None
    }
}

impl From<threshold_crypto::error::Error> for Error {
    fn from(_: threshold_crypto::error::Error) -> Self {
        Error::None
    }
}

/// It rapresent a member as (membername, password)
type Member = (String, Secret<Vec<u8>>);

use threshold_crypto::SecretKeySet;

const SEED_LENGTH: u16 = 500;

/// Generate and encrypt the seed with the member secrets.
/// Derive users' branches.
#[derive(Debug, Serialize, Deserialize)]
pub struct Root {
    encrypted_seed: Vec<u8>,
    group_dimension: u8,
    pub subset_min_dimension: u8,
    encryptd_members: Vec<GroupMember>,
    pk: PublicKeySet,
    // add control field (is a hash of the seed + unknown user) is checked each time to verify
    // that the password provided is good
}

impl Root {
    /// Return a Root, creating a random seed and encrypting it with the given passwords.
    ///
    /// # Arguments
    ///
    /// * `subset_min_dimension` - Can not be bigger than members.len(), minimum value 1
    /// * `members` - A vector of `(username, password)`, minimum length is 1 max is 255 panic
    /// if there are two equal usernames
    ///
    /// # Example
    /// ```
    /// use secrecy::Secret;
    /// use shrd_sec_lib::Root;
    /// let member1 = ("user1".to_string(), Secret::new(b"bona cisi ciao bona".to_vec()));
    /// let member2 = ("user2".to_string(), Secret::new(b"cisi cisi ciao bona".to_vec()));
    /// let member3 = ("user3".to_string(), Secret::new(b"ciao cisi ciao bona".to_vec()));
    /// let root = Root::new(2, vec![member1, member2, member3]).unwrap();
    /// ```
    pub fn new(subset_min_dimension: u8, members: Vec<Member>) -> Result<Self, Error> {
        if has_duplicate(members.iter().map(|x| x.0.clone()).collect()) {
            panic!("Usernames must be unique")
        }
        let sk_set = make_key_set(subset_min_dimension);
        let encrypted_seed = new_random_encrypted_seed(&sk_set);
        let group_dimension = members.len() as u8;
        let pk = sk_set.public_keys();
        let encryptd_members = members_from_key_set(members, sk_set)?;
        Ok(Root {
            encrypted_seed,
            group_dimension,
            subset_min_dimension,
            encryptd_members,
            pk,
        })
    }

    /// Return a Secret containing the unencrypted user's seed
    ///
    /// # Arguments
    /// * `members` - vector of `Member`s that want to generate the new user's seed the vector len must
    /// be greater or equal than `subset_min_dimension`;
    /// * `username` - `&str` is the username for which the seed is generated
    ///
    /// # Example
    /// ```
    /// # use secrecy::Secret;
    /// # use secrecy::ExposeSecret;
    /// # use shrd_sec_lib::Root;
    /// # let member1 = ("user1".to_string(), Secret::new(b"bona cisi ciao bona".to_vec()));
    /// # let member2 = ("user2".to_string(), Secret::new(b"cisi cisi ciao bona".to_vec()));
    /// # let member3 = ("user3".to_string(), Secret::new(b"ciao cisi ciao bona".to_vec()));
    /// let root = Root::new(2, vec![member1, member2, member3]).unwrap();
    /// # let member1 = ("user1".to_string(), Secret::new(b"bona cisi ciao bona".to_vec()));
    /// # let member2 = ("user2".to_string(), Secret::new(b"cisi cisi ciao bona".to_vec()));
    /// let seed_from_menber1_and_2 =root.new_user_seed(& vec![member1,member2], & b"gigi".to_vec()).unwrap();
    /// # let member2 = ("user2".to_string(), Secret::new(b"cisi cisi ciao bona".to_vec()));
    /// # let member3 = ("user3".to_string(), Secret::new(b"ciao cisi ciao bona".to_vec()));
    /// let seed_from_menber2_and_3 =root.new_user_seed(& vec![member2,member3], & b"gigi".to_vec()).unwrap();
    /// # let member1 = ("user1".to_string(), Secret::new(b"bona cisi ciao bona".to_vec()));
    /// # let member3 = ("user3".to_string(), Secret::new(b"ciao cisi ciao bona".to_vec()));
    /// let seed_from_menber1_and_3 =root.new_user_seed(& vec![member1,member3], & b"gigi".to_vec()).unwrap();
    /// assert_eq!(seed_from_menber1_and_2.expose_secret(),
    /// seed_from_menber2_and_3.expose_secret());
    /// assert_eq!(seed_from_menber2_and_3.expose_secret(), seed_from_menber1_and_3.expose_secret());
    /// ```
    pub fn new_user_seed(
        &self,
        members: &Vec<Member>,
        username: &Vec<u8>,
    ) -> Result<Secret<Vec<u8>>, Error> {
        if members.len() < self.subset_min_dimension as usize {
            //TODO
            panic!("not enough members");
        }
        let mut seed = self.get_seed(members)?.expose_secret().clone();
        for byte in username.iter() {
            seed.push(*byte);
        }
        let seed = Secret::new(seed);
        let seed = crypto::hash_secret(&seed);
        Ok(seed)
    }

    /// Return a Secret containing the unencrypted seed.
    fn get_seed(&self, members: &Vec<Member>) -> Result<Secret<Vec<u8>>, Error> {
        let members = self.decrypt_secrets(members)?;
        let ciphertext: Ciphertext = bincode::deserialize(&self.encrypted_seed[..]).unwrap();
        let mut shares = BTreeMap::new();
        for member in members.iter() {
            // TODO check that it doesn't leack the seed
            let secret_key_share: SecretKeyShare =
                bincode::deserialize(&member.1.expose_secret()).unwrap();
            let dec_share = secret_key_share.decrypt_share(&ciphertext)?;
            let member_id = self
                .encryptd_members
                .iter()
                .filter(|x| x.username == member.0)
                .collect::<Vec<&GroupMember>>()[0]
                .id;
            shares.insert(member_id, dec_share);
        }
        let seed = self.pk.decrypt(&shares, &ciphertext)?;
        Ok(Secret::new(seed))
    }

    /// Return a vector of `(membername, shared_secret)`
    fn decrypt_secrets<'a>(
        &'a self,
        members: &'a Vec<Member>,
    ) -> Result<Vec<(String, Secret<Vec<u8>>)>, Error> {
        let mut secrets = vec![];
        for member in members {
            let encrypted_member = self
                .encryptd_members
                .iter()
                .filter(|x| x.username == member.0)
                .collect::<Vec<&GroupMember>>();
            match encrypted_member.get(0) {
                Some(encrypted_member) => {
                    let secret = encrypted_member.get_secret(&member.1)?;
                    secrets.push((member.0.clone(), secret));
                }
                None => return Err(Error::InvalidUser),
            }
        }
        Ok(secrets)
    }
}

#[test]
#[should_panic]
fn test_new_root_panic_with_equale_usernames() {
    let member1 = (
        "user".to_string(),
        Secret::new(b"bona cisi ciao bona".to_vec()),
    );
    let member2 = (
        "user".to_string(),
        Secret::new(b"cisi cisi ciao bona".to_vec()),
    );
    Root::new(2, vec![member1, member2]);
}

#[test]
fn test_new_user_seed_diff_users_diff_seeds() {
    let member1 = (
        "user1".to_string(),
        Secret::new(b"bona cisi ciao bona".to_vec()),
    );
    let member2 = (
        "user2".to_string(),
        Secret::new(b"cisi cisi ciao bona".to_vec()),
    );
    let member3 = (
        "user3".to_string(),
        Secret::new(b"ciao cisi ciao bona".to_vec()),
    );
    let root = Root::new(2, vec![member1, member2, member3]).unwrap();
    let member1 = (
        "user1".to_string(),
        Secret::new(b"bona cisi ciao bona".to_vec()),
    );
    let member2 = (
        "user2".to_string(),
        Secret::new(b"cisi cisi ciao bona".to_vec()),
    );
    let seed_for_user1 = root
        .new_user_seed(&vec![member1, member2], &b"user1".to_vec())
        .unwrap();
    let member1 = (
        "user1".to_string(),
        Secret::new(b"bona cisi ciao bona".to_vec()),
    );
    let member2 = (
        "user2".to_string(),
        Secret::new(b"cisi cisi ciao bona".to_vec()),
    );
    let seed_for_user2 = root
        .new_user_seed(&vec![member1, member2], &b"user2".to_vec())
        .unwrap();
    assert_ne!(
        seed_for_user1.expose_secret(),
        seed_for_user2.expose_secret()
    );
}

fn has_duplicate<T: std::cmp::Ord>(mut v: Vec<T>) -> bool {
    v.sort();
    let len_ = v.len();
    v.dedup();
    if v.len() == len_ {
        false
    } else {
        true
    }
}

fn make_key_set(threshold: u8) -> SecretKeySet {
    let mut rng = rand::thread_rng();
    let threshold = threshold - 1;
    SecretKeySet::random(threshold as usize, &mut rng)
}

fn new_random_encrypted_seed(sk_set: &SecretKeySet) -> Vec<u8> {
    let seed = crypto::new_nonce(SEED_LENGTH as usize);
    bincode::serialize(&sk_set.public_keys().public_key().encrypt(seed)).unwrap()
}

fn members_from_key_set(
    members: Vec<Member>,
    key_set: SecretKeySet,
) -> Result<Vec<GroupMember>, Error> {
    let mut encrypted_members = vec![];
    for (i, member) in members.iter().enumerate() {
        let shared_secret: Vec<u8> =
            // TODO check if serdesecret is zeroized
            bincode::serialize(&SerdeSecret(key_set.secret_key_share(i))).unwrap();
        let member = GroupMember::new(member.0.to_string(), &member.1, shared_secret, i)?;
        encrypted_members.push(member);
    }
    Ok(encrypted_members)
}
