extern crate tealeaves;
use std::fs;
use std::io::Read;
use tealeaves::parse::private_key;
use tealeaves::file_info::Algorithm;

fn test_vec(length: usize) -> Vec<u8> {
    let mut modulus = vec!();
    modulus.resize(length, 0);
    modulus
}

#[test]
fn rsa_1024_private_passphrase() {
    let mut file = fs::File::open("./files/ssh-rsa-2048-b-private-key-passphrase.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Rsa(test_vec(0)));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, true);
            assert_eq!(ssh_key.comment, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn dsa_1024_private_clear() {
    let mut file = fs::File::open("./files/ssh-dsa-1024-a-private-key.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Dsa(1024));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn dsa_1024_private_passphrase() {
    let mut file = fs::File::open("./files/ssh-dsa-1024-b-private-key-passphrase.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Dsa(1024));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, true);
            assert_eq!(ssh_key.comment, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn ecdsa_256_private_clear() {
    let mut file = fs::File::open("files/ssh-ecdsa-256-a-private-key.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Ecdsa(256));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn ed25519_private_clear() {
    let mut file = fs::File::open("./files/ssh-ed25519-a-private-key.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Ed25519);
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn ed25519_private_passphrase() {
    let mut file = fs::File::open("./files/ssh-ed25519-b-private-key-passphrase.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Ed25519);
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, true);
            assert_eq!(ssh_key.comment, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn rsa_1024_private_clear() {
    let mut file = fs::File::open("./files/ssh-rsa-1024-a-private-key.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Rsa(test_vec(2048)));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn rsa_2048_private_clear() {
    let mut file = fs::File::open("./files/ssh-rsa-2048-a-private-key.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Rsa(test_vec(2048)));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn rsa_4096_private_clear() {
    let mut file = fs::File::open("./files/ssh-rsa-4096-a-private-key.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Rsa(test_vec(4096)));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}
