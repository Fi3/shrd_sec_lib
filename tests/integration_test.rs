use secrecy::Secret;
use shrd_sec_lib::Root;

#[test]
fn test() {
    let member1 = (
        "user1".to_string(),
        Secret::new(b"abcdefghilmnopqr".to_vec()),
    );
    let member2 = (
        "user2".to_string(),
        Secret::new(b"abcdefghilmnopqrs".to_vec()),
    );
    let member3 = (
        "user3".to_string(),
        Secret::new(b"abcdefghilmnopqrst".to_vec()),
    );
    Root::new(2, vec![member1, member2, member3]).unwrap();
}
