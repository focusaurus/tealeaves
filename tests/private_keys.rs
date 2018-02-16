extern crate rsfs;
extern crate tealeaves;
use tealeaves::leaf::Leaf;
use tealeaves::ssh_key::Algorithm;

fn test_vec(length: usize) -> Vec<u8> {
    let mut modulus = vec![];
    modulus.resize(length, 0);
    modulus
}

fn scan(path: &str) -> Leaf {
    tealeaves::scan(&rsfs::disk::FS, &path).unwrap()
}

#[test]
fn rsa_1024_private_passphrase_scan() {
    match scan("./files/ssh-rsa-2048-b-private-key-passphrase.pem") {
        Leaf::SshKey(_path, ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Rsa(test_vec(0)));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, true);
            assert_eq!(ssh_key.comment, None);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn dsa_1024_private_clear() {
    match scan("./files/ssh-dsa-1024-a-private-key.pem") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Dsa(p_integer) => assert_eq!(p_integer.len() * 8, 1024),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn dsa_1024_private_passphrase() {
    match scan("./files/ssh-dsa-1024-b-private-key-passphrase.pem") {
        Leaf::SshKey(_path, ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Dsa(vec![]));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, true);
            assert_eq!(ssh_key.comment, None);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn ecdsa_256_private_clear() {
    match scan("files/ssh-ecdsa-256-a-private-key.pem") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Ecdsa(ref curve, ref point) => {
                    assert_eq!(curve, "nistp256");
                    assert_eq!(point.len(), 65);
                }
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn ed25519_private_clear() {
    match scan("./files/ssh-ed25519-a-private-key.pem") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Ed25519(point) => assert_eq!(point.len(), 32),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn ed25519_private_passphrase() {
    match scan("./files/ssh-ed25519-b-private-key-passphrase.pem") {
        Leaf::SshKey(_path, ssh_key) => {
            assert_eq!(ssh_key.algorithm, Algorithm::Ed25519(vec![]));
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, true);
            assert_eq!(ssh_key.comment, None);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn rsa_1024_private_clear() {
    match scan("./files/ssh-rsa-1024-a-private-key.pem") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Rsa(modulus) => assert_eq!(modulus.len() * 8, 1024),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn rsa_2048_private_clear() {
    match scan("./files/ssh-rsa-2048-a-private-key.pem") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Rsa(modulus) => assert_eq!(modulus.len() * 8, 2048),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn rsa_4096_private_clear() {
    match scan("./files/ssh-rsa-4096-a-private-key.pem") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Rsa(modulus) => assert_eq!(modulus.len() * 8, 4096),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, false);
            assert_eq!(ssh_key.is_encrypted, false);
            assert_eq!(ssh_key.comment, None);
        }
        _ => panic!("Expected SshKey"),
    }
}
