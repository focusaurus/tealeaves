use std::{fmt, path};
use ssh_key::{Algorithm, SshKey};
use certificate::Certificate;

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
    Certificate(path::PathBuf, Certificate),
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
                    Algorithm::Ecdsa(_, _) => {
                        output.push_str("\n\t⚠️ ecdsa keys are considered insecure");
                    }
                    _ => (),
                }
                // TODO figure out how to handle this
                // if !key.is_public && self.mode.unwrap_or(0o000) & 0o077 != 0o000 {
                //     output.push_str("\n\t⚠️ insecure permissions");
                // }
            }
            Leaf::Certificate(ref path_buf, ref certificate) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));
                output.push_str(&format!("\n\t✓ {}", certificate));
            }
            Leaf::Error(ref path_buf, ref message) => {
                output.push_str(path_buf.to_str().unwrap_or("/"));
                output.push_str(&format!("\t🚨 Error: {}", message))
            }
        };
        write!(out, "{}\n", output)
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
        ssh_key.algorithm = Algorithm::Ecdsa("nistp384".into(), vec![]);
        ssh_key.is_encrypted = false;
        ssh_key.is_public = false;
        let leaf = Leaf::SshKey(PathBuf::from("/unit-test"), ssh_key);
        assert_eq!(
            format!("{}", leaf),
            "/unit-test
\t✓ private ssh key (ecdsa, curve nistp384, not encrypted)
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
