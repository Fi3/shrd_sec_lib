extern crate base64;
extern crate bincode;
extern crate clap;
extern crate rpassword;
extern crate secrecy;
extern crate shrd_sec_lib;
extern crate text_io;

use base64::encode;
use clap::{App, Arg, SubCommand};
use rpassword::read_password_from_tty;
use secrecy::ExposeSecret;
use secrecy::Secret;
use shrd_sec_lib::root::root::{Error, Root};
use shrd_sec_lib::user::User;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use text_io::scan;

fn main() {
    let matches = App::new("Secret generator")
        .version("0.0.1")
        .author("Filippo Merli")
        .about("Do not use it for anything that must be secure :)")
        .subcommand(
            SubCommand::with_name("new-root")
                .help("Create a new encrypted root")
                .arg(
                    Arg::with_name("member-number")
                        .short("n")
                        .long("member-number")
                        .help("Group's dimension")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("secrets")
                        .short("s")
                        .long("secrets")
                        .help("Number of member's secret needed to decrypt the root's seed")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .help("Path of the encrypted root is saved")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("create-user")
                .help("Create a new user")
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .help("Path of the encrypted user is saved")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("username")
                        .short("u")
                        .long("username")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("root")
                        .short("r")
                        .long("root")
                        .help("Path to the file containing the encrypted root")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .subcommand(
            SubCommand::with_name("get-secret")
                .help("Create a new user")
                .arg(
                    Arg::with_name("path")
                        .short("p")
                        .long("username")
                        .help("Leaf of the secret's tree")
                        .required(true)
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("user")
                        .short("u")
                        .long("user")
                        .help("Path to the file containing the encrypted user")
                        .required(true)
                        .takes_value(true),
                ),
        )
        .get_matches();

    match matches.subcommand_matches("new-root") {
        Some(matches) => {
            let output_file = matches.value_of("output").unwrap();
            let group_dimension = matches.value_of("member-number").unwrap();
            let min_subset = matches.value_of("secrets").unwrap();
            let root = create_root(group_dimension, min_subset).unwrap();
            let mut file = File::create(matches.value_of("output").unwrap()).unwrap();
            let root: Vec<u8> = bincode::serialize(&root).unwrap();
            file.write_all(&root).unwrap();
            println!("Created new root belonging to {} members, decryptable by a min subset of {} members in {}", group_dimension, min_subset, output_file);
        }
        _ => (),
    }

    match matches.subcommand_matches("create-user") {
        Some(matches) => {
            let mut file = File::open(matches.value_of("root").unwrap()).unwrap();
            let mut root = Vec::<u8>::new();
            file.read_to_end(&mut root).unwrap();
            let output_file = matches.value_of("output").unwrap();
            let root: Root = bincode::deserialize(&root).unwrap();
            let members = get_min_root_subset(&root);
            let username = matches.value_of("username").unwrap();
            let password = get_pwd(format!("Insert password for {}", username));
            let username = username.as_bytes().to_vec();
            let user = shrd_sec_lib::create_user(&root, &members, &username, &password).unwrap();
            let mut file = File::create(matches.value_of("output").unwrap()).unwrap();
            let user = bincode::serialize(&user).unwrap();
            file.write_all(&user).unwrap();
            println!(
                "Created new user with username: {}, in: {}",
                String::from_utf8(username).unwrap(),
                output_file
            );
        }
        _ => (),
    }
    match matches.subcommand_matches("get-secret") {
        Some(matches) => {
            let mut file = File::open(matches.value_of("user").unwrap()).unwrap();
            let mut user = Vec::<u8>::new();
            file.read_to_end(&mut user).unwrap();
            let user: User = bincode::deserialize(&user).unwrap();
            let password = get_pwd(format!(
                "Insert user password for {}",
                String::from_utf8(user._username.clone()).unwrap()
            ));
            let path = matches.value_of("path").unwrap().as_bytes().to_vec();
            let secret = user.get_path(&path, &password);
            println!(
                "The secret for the path {} is: {}",
                String::from_utf8(path).unwrap(),
                encode(secret.unwrap().expose_secret())
            );
        }
        _ => (),
    }
}

fn create_root(group_dimension: &str, min_subset: &str) -> Result<Root, Error> {
    let group_dimension = group_dimension.parse::<u8>().unwrap() - 1;
    let min_subset = min_subset.parse::<u8>().unwrap();
    let mut members_name = vec![];
    let mut members = vec![];
    let mut membername: String;
    let mut password: Secret<Vec<u8>>;
    for i in 0..group_dimension {
        println!("Insert membername for member {}", i + 1);
        scan!("{}", membername);
        members_name.push(membername);
    }
    for member in members_name {
        password = get_pwd(format!("Insert password for member {}", member));
        members.push((member, password));
    }
    Root::new(min_subset, members)
}

fn get_min_root_subset(root: &Root) -> Vec<(String, Secret<Vec<u8>>)> {
    let min_subset = root.subset_min_dimension;
    let mut membername: String;
    let mut password: Secret<Vec<u8>>;
    let mut members = vec![];
    for i in 0..min_subset {
        println!("Insert membername for member {}", i + 1);
        scan!("{}", membername);
        password = get_pwd(format!("Insert password for member {}", membername));
        members.push((membername, password));
    }
    members
}

fn get_pwd(message: String) -> Secret<Vec<u8>> {
    println!("{}", message);
    let password1 = read_password_from_tty(None).unwrap().as_bytes().to_vec();
    println!("Renter password");
    let password2 = read_password_from_tty(None).unwrap().as_bytes().to_vec();
    if password1 == password2 {
        Secret::new(password1)
    } else {
        println!("Password do not match");
        get_pwd(message)
    }
}
