extern crate tealeaves;
use std::fs;
use std::io::Read;
use tealeaves::parse::private_key;

/*
files/ssh-rsa-1024-a-private-key.pem
files/ssh-rsa-1024-b-private-key.pem
files/ssh-rsa-2048-a-private-key.pem
files/ssh-rsa-2048-b-private-key-passphrase.pem
files/ssh-rsa-4096-a-private-key.pem
*/

#[test]
fn dsa_1024_private_clear() {
    let mut file = fs::File::open("./files/ssh-dsa-1024-a-private-key.pem").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();
    match private_key(&key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("dsa".to_string()));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
            assert_eq!(ssh_key.key_length, Some(1024));
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
            assert_eq!(ssh_key.algorithm, Some("dsa".to_string()));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, true);
            assert_eq!(ssh_key.comment, None);
            assert_eq!(ssh_key.key_length, None);
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
            assert_eq!(ssh_key.algorithm, Some("ecdsa".to_string()));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
            assert_eq!(ssh_key.key_length, Some(256));
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn private_rsa_pem_asn() {
    let mut file = fs::File::open("./files/ssh-ecdsa-256-a-public-key").unwrap();
    let mut key_bytes = vec![];
    file.read_to_end(&mut key_bytes).unwrap();

    let key_bytes = b"-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCjR11YkCFYeJOQKGn1JMZJOFbDrUbyju7nk6Itoz39DGkPZ6mb
Os7z3Mh39K2Y+5H+tsOdJaKIca1zoDvHFDpVnejrIuPKaacspgWaf/VSaHjeltKd
gvIie+Awjvsen1+/JWwR815+6CE5YZgLIIZmRj9IwRWohKq8G6dwXzKTpwIDAQAB
AoGAO/pZFdFMDn2sZwYRdhWeKQNjC9o495z9sV+P8YfHm47VgO0pZnZB017E3Ruq
MUooJRLp5G4QuGJZvuGbU9PgYUC2sr+q+UNLklaeX2fNfZDe7rD7YJ/NrLg1GNpu
fzncXDm/tyY2JFj65JwDEnM4eZ4RBBg8tAFacbXxzqkd1iECQQDQfc1EM+6931yj
GGQ8S2BmvDfr0B6blGjouXoNlUKxWtI2JHpD81uaVKzHOY75sCg2WMoQPhs+Lu1L
+fCyq/S/AkEAyHwdhpPcHWJOMOZif9eSRtoRqsD5VGcZMiajSM+w7CxgVRbLc6Ry
1Vi1R1JmZEUEa7TgIFcicmAgj3RIMqKTGQJACytiLtA1bxijRt2MqSpEnNxihpCc
wyr9P9KH9mhTrVq3Pk1P+4nzE16L7xRnU3sbfGXfVWVuYjNzZQmb2oaZ0wJAOU8x
aXzu2P929oeE9KJ80AAaOMN9AmGOVEWzO2cTXg+5YdloQyBpKw92knK9jkAkaV2F
C/mcgTF1XUySLtdGUQJAVN/mhZoMo99dhbvAMbbaRCivQyhikVcEVJWu3J8wVrJT
jr9RP7zEv+edSjWnzDr+33m3+FaZfLN4PfrQUqbKBg==
-----END RSA PRIVATE KEY-----
";
    match private_key(key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("rsa".to_string()));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.comment, None);
            assert_eq!(ssh_key.key_length, Some(1024));
            assert_eq!(ssh_key.is_encrypted, false);
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
            assert_eq!(ssh_key.algorithm, Some("ed25519".to_string()));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
            assert_eq!(ssh_key.key_length, None);
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
            assert_eq!(ssh_key.algorithm, Some("ed25519".to_string()));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, true);
            assert_eq!(ssh_key.comment, None);
            assert_eq!(ssh_key.key_length, None);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}
