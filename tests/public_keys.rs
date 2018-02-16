extern crate rsfs;
extern crate tealeaves;
use tealeaves::Leaf;
use tealeaves::ssh_key::Algorithm;

fn scan(path: &str) -> Leaf {
    tealeaves::scan(&rsfs::disk::FS, &path).unwrap()
}

#[test]
fn ed25519_public() {
    match scan("./files/ssh-ed25519-a-public-key") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Ed25519(point) => assert_eq!(point.len(), 32),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn rsa_1024_public() {
    match scan("./files/ssh-rsa-1024-a-public-key") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Rsa(modulus) => assert_eq!(modulus.len() * 8, 1024),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn rsa_2048_public() {
    match scan("./files/ssh-rsa-2048-a-public-key") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Rsa(modulus) => assert_eq!(modulus.len() * 8, 2048),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn dsa_public() {
    match scan("./files/ssh-dsa-1024-a-public-key") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Dsa(p_integer) => assert_eq!(p_integer.len() * 8, 1024),
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn ecdsa_256_public() {
    match scan("./files/ssh-ecdsa-256-a-public-key") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Ecdsa(ref curve, ref point) => {
                    assert_eq!(curve, "nistp256");
                    assert_eq!(point.len(), 65);
                }
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn ecdsa_384_public() {
    match scan("./files/ssh-ecdsa-384-a-public-key") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Ecdsa(ref curve, ref point) => {
                    assert_eq!(curve, "nistp384");
                    assert_eq!(point.len(), 97);
                }
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn ecdsa_521_public() {
    match scan("./files/ssh-ecdsa-521-a-public-key") {
        Leaf::SshKey(_path, ssh_key) => {
            match ssh_key.algorithm {
                Algorithm::Ecdsa(ref curve, ref point) => {
                    assert_eq!(curve, "nistp521");
                    assert_eq!(point.len(), 133);
                }
                _ => panic!("algorithm not detected correctly"),
            };
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".into()));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        _ => panic!("Expected SshKey"),
    }
}
