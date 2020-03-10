#![feature(try_trait)]

extern crate secrecy;
extern crate serde;

pub mod root;
pub mod user;
pub mod utils;

pub use root::group_member;
pub use root::root::Root;
use secrecy::Secret;
use user::User;

pub fn create_user(
    root: &Root,
    members: &Vec<(String, Secret<Vec<u8>>)>,
    username: &Vec<u8>,
    password: &Secret<Vec<u8>>,
) -> Result<User, root::root::Error> {
    let seed = root.new_user_seed(members, username)?;
    Ok(User::new(username.to_vec(), &seed, password)?)
}
