extern crate tealeaves;

use std::fs;
use std::io::Read;

use tealeaves::parse::public_key;

#[test]
fn public_ed25519() {
    let mut file = fs::File::open("./files/ssh-ed25519-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("ed25519".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment,
                       Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, None);
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_rsa_1024() {
    let mut file = fs::File::open("./files/ssh-rsa-1024-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("rsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(1024));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_rsa_2048() {
    let mut file = fs::File::open("./files/ssh-rsa-2048-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("rsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(2048));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_dsa() {
    let mut file = fs::File::open("./files/ssh-dsa-1024-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("dsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(1024));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_ecdsa_256() {
    let mut file = fs::File::open("./files/ssh-ecdsa-256-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("ecdsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(256));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_ecdsa_384() {
    let mut file = fs::File::open("./files/ssh-ecdsa-384-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("ecdsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(384));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_ecdsa_521() {
    let mut file = fs::File::open("./files/ssh-ecdsa-521-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("ecdsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(521));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}
