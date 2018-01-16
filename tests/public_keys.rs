extern crate tealeaves;
use std::fs;
use std::io::Read;
use tealeaves::leaf::Algorithm;
use tealeaves::parse::public_key;

#[test]
fn ed25519_public() {
    let mut file = fs::File::open("./files/ssh-ed25519-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Ed25519(point) => assert_eq!(point.len(), 32),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn rsa_1024_public() {
    let mut file = fs::File::open("./files/ssh-rsa-1024-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Rsa(modulus) => assert_eq!(modulus.len() * 8, 1024),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn rsa_2048_public() {
    let mut file = fs::File::open("./files/ssh-rsa-2048-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Rsa(modulus) => assert_eq!(modulus.len() * 8, 2048),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn dsa_public() {
    let mut file = fs::File::open("./files/ssh-dsa-1024-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Dsa(p_integer) => assert_eq!(p_integer.len() * 8, 1024),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn ecdsa_256_public() {
    let mut file = fs::File::open("./files/ssh-ecdsa-256-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Ecdsa(256));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn ecdsa_384_public() {
    let mut file = fs::File::open("./files/ssh-ecdsa-384-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Ecdsa(384));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn ecdsa_521_public() {
    let mut file = fs::File::open("./files/ssh-ecdsa-521-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match public_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Ecdsa(521));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}
