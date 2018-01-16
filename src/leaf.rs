use std::{fmt, path};

#[derive(PartialEq, Eq, Debug)]
pub enum Algorithm {
    Unknown,
    Ed25519(Vec<u8>),
    Rsa(Vec<u8>),
    Ecdsa(usize),
    Dsa(Vec<u8>),
}

impl fmt::Display for Algorithm {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Algorithm::Ed25519(_) => write!(out, "ed25519"),
            &Algorithm::Rsa(_) => write!(out, "rsa"),
            &Algorithm::Ecdsa(curve) => write!(out, "ecdsa, curve p{}", curve),
            &Algorithm::Dsa(_) => write!(out, "dsa"),
            _ => write!(out, "unknown"),
        }
    }
}

#[derive(Debug)]
pub enum Leaf {
    Unknown(path::PathBuf),
    Error(path::PathBuf, String),
    Directory(path::PathBuf),
    UnreadableFile(path::PathBuf),
    EmptyFile(path::PathBuf),
    SmallFile(path::PathBuf),
    MediumFile(path::PathBuf),
    LargeFile(path::PathBuf),
    SshKey(path::PathBuf, SshKey),
    TlsCertificate(path::PathBuf),
}

impl fmt::Display for Leaf {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        match *self {
            Leaf::Unknown(ref path_buf) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));
                output.push_str("\n\t⚠️ unrecognized file");
            }
            Leaf::Directory(ref path_buf) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));
                output.push_str("\n\t✓ is a directory");
            }
            Leaf::UnreadableFile(ref path_buf) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));

                output.push_str("\n\t🔥 missing read permission");
            }
            Leaf::EmptyFile(ref path_buf) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));
                output.push_str("\n\t⚠️ empty file");
            }
            Leaf::SmallFile(ref path_buf) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));

                output.push_str("\n\t⚠️ unrecognized small file")
            }
            Leaf::MediumFile(ref path_buf) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));

                output.push_str("\n\t⚠️ unrecognized medium file")
            }
            Leaf::LargeFile(ref path_buf) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));
                output.push_str("\n\t⚠️ unrecognized large file")
            }
            Leaf::SshKey(ref path_buf, ref key) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));
                output.push_str(&format!("\n\t✓ {}", key));

                match key.algorithm {
                    Algorithm::Rsa(ref modulus) => {
                        if !key.is_encrypted && modulus.len() < (2048 / 8) {
                            output.push_str("\n\t⚠️ RSA keys should be 2048 bits or larger");
                        }
                    }
                    Algorithm::Dsa(_) => {
                        output.push_str("\n\t⚠️ dsa keys are considered insecure");
                    }
                    Algorithm::Ecdsa(_) => {
                        output.push_str("\n\t⚠️ ecdsa keys are considered insecure");
                    }
                    _ => (),
                }
                // TODO figure out how to handle this
                // if !key.is_public && self.mode.unwrap_or(0o000) & 0o077 != 0o000 {
                //     output.push_str("\n\t⚠️ insecure permissions");
                // }
            }
            Leaf::TlsCertificate(ref _path_buf) => output.push_str("\t⚠️ TLS certificate"),
            Leaf::Error(ref _path_buf, ref message) => {
                output.push_str(&format!("\t🚨 Error: {}", message))
            }
        };
        write!(out, "{}\n", output)
    }
}

#[derive(Debug)]
pub struct CertificateRequest {
    pub is_encrypted: bool,
}

impl CertificateRequest {
    pub fn new() -> Self {
        Self {
            is_encrypted: false,
        }
    }
}

impl Default for CertificateRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SshKey {
    pub algorithm: Algorithm,
    pub comment: Option<String>,
    pub is_encrypted: bool,
    pub is_public: bool,
    pub point: Option<Vec<u8>>,
}

impl SshKey {
    pub fn new() -> Self {
        Self {
            algorithm: Algorithm::Unknown,
            comment: None,
            is_encrypted: false,
            is_public: false,
            point: None,
        }
    }

    pub fn is_pair(&self, other: &SshKey) -> bool {
        if self.is_public == other.is_public {
            return false;
        }
        match self.algorithm {
            Algorithm::Ed25519(ref point) => match other.algorithm {
                Algorithm::Ed25519(ref point2) => point == point2,
                _ => false,
            },
            Algorithm::Rsa(ref modulus) => match other.algorithm {
                Algorithm::Rsa(ref modulus2) => modulus == modulus2,
                _ => false,
            },
            Algorithm::Dsa(ref p_integer) => match other.algorithm {
                Algorithm::Dsa(ref p_integer2) => p_integer == p_integer2,
                _ => false,
            },
            _ => false,
        }
    }
}

#[test]
fn test_is_pair() {
    let mut priv1: SshKey = Default::default();
    priv1.algorithm = Algorithm::Rsa(vec![1, 2, 3]);
    assert!(!priv1.is_pair(&priv1));
    let mut pub1: SshKey = Default::default();
    pub1.is_public = true;
    pub1.algorithm = Algorithm::Rsa(vec![1, 2, 3]);
    assert!(priv1.is_pair(&pub1));
    assert!(pub1.is_pair(&priv1));
    let mut pub2: SshKey = Default::default();
    pub2.is_public = true;
    pub2.algorithm = Algorithm::Dsa(vec![1, 2, 3]);
    assert!(!pub2.is_pair(&priv1));
    let mut pub3: SshKey = Default::default();
    pub3.is_public = true;
    pub3.algorithm = Algorithm::Rsa(vec![4, 5, 6]);
    assert!(!pub3.is_pair(&priv1));
    assert!(!priv1.is_pair(&pub3));
    let mut priv2: SshKey = Default::default();
    priv2.algorithm = Algorithm::Dsa(vec![4, 5, 6]);
    assert!(!priv2.is_pair(&priv2));
    assert!(!priv2.is_pair(&pub1));
    assert!(!priv2.is_pair(&priv1));

    let mut pub4: SshKey = Default::default();
    pub4.is_public = true;
    pub4.algorithm = Algorithm::Dsa(vec![4, 5, 6]);
    assert!(pub4.is_pair(&priv2));
    assert!(priv2.is_pair(&pub4));
    assert!(!pub4.is_pair(&priv1));
}

fn bit_count(field: &Vec<u8>) -> usize {
    field.len() * 8
}

impl fmt::Display for SshKey {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        if self.is_public {
            output.push_str("public ");
        } else {
            output.push_str("private ");
        }
        output.push_str("ssh key (");
        output.push_str(&format!("{}", self.algorithm));
        if !self.is_encrypted {
            match self.algorithm {
                Algorithm::Rsa(ref modulus) => {
                    output.push_str(&format!(", {} bits", bit_count(modulus)));
                }
                Algorithm::Dsa(ref p_integer) => {
                    output.push_str(&format!(", {} bits", bit_count(p_integer)));
                }
                _ => (),
            }
        }
        if !self.is_public {
            output.push_str(", ");
            if self.is_encrypted {
                output.push_str("encrypted");
            } else {
                output.push_str("not encrypted");
            }
        }
        output.push_str(")");
        write!(out, "{}", output)
    }
}

impl Default for SshKey {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use super::{Algorithm, Leaf, SshKey};

    #[test]
    fn test_leaf_display_encrypted_ed25519() {
        let mut ssh_key: SshKey = Default::default();
        ssh_key.algorithm = Algorithm::Ed25519(vec![]);
        ssh_key.is_public = false;
        ssh_key.is_encrypted = true;
        let leaf = Leaf::SshKey(PathBuf::from("/unit-test"), ssh_key);
        assert_eq!(
            format!("{}", leaf),
            "/unit-test\n\t✓ private ssh key (ed25519, encrypted)\n"
        );
    }

    #[test]
    fn test_leaf_display_encrypted_ecdsa() {
        let mut ssh_key: SshKey = Default::default();
        ssh_key.algorithm = Algorithm::Ecdsa(384);
        ssh_key.is_encrypted = false;
        ssh_key.is_public = false;
        let leaf = Leaf::SshKey(PathBuf::from("/unit-test"), ssh_key);
        assert_eq!(
            format!("{}", leaf),
            "/unit-test
\t✓ private ssh key (ecdsa, curve p384, not encrypted)
\t⚠️ ecdsa keys are considered insecure
"
        );
    }

    #[test]
    fn test_leaf_display_rsa_public() {
        let mut modulus = vec![];
        modulus.extend_from_slice(&[0u8; 256]);
        let mut ssh_key: SshKey = Default::default();
        ssh_key.algorithm = Algorithm::Rsa(modulus);
        ssh_key.is_public = true;
        let leaf = Leaf::SshKey(PathBuf::from("/unit-test"), ssh_key);
        assert_eq!(
            "/unit-test\n\t✓ public ssh key (rsa, 2048 bits)\n",
            format!("{}", leaf)
        );
    }

    #[test]
    fn test_leaf_display_rsa_private_passphrase() {
        let mut ssh_key: SshKey = Default::default();
        ssh_key.is_encrypted = true;
        ssh_key.algorithm = Algorithm::Rsa(vec![]);
        let leaf = Leaf::SshKey(PathBuf::from("/unit-test"), ssh_key);
        assert_eq!(
            "/unit-test\n\t✓ private ssh key (rsa, encrypted)\n",
            format!("{}", leaf)
        );
    }
}
