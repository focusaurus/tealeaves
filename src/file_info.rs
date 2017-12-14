use std::{fmt, path};

#[derive(PartialEq, Eq, Debug)]
pub enum Size {
    Unknown,
    Small,
    Medium,
    Large,
}

#[derive(PartialEq, Eq, Debug)]
pub enum Algorithm {
    Unknown,
    Ed25519,
    Rsa(usize),
    Ecdsa(usize),
    Dsa(usize),
}

#[derive(Debug)]
pub struct SshKey {
    // pub algorithm: Option<String>,
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
        output.push_str(&match self.algorithm {
            Algorithm::Ed25519 => "ed25519".to_string(),
            Algorithm::Ecdsa(ref curve) => format!("ecdsa, curve p{}", curve),
            Algorithm::Rsa(_) => "rsa".to_string(),
            Algorithm::Dsa(_) => "dsa".to_string(),
            Algorithm::Unknown => "unknown".to_string(),
        });
        if !self.is_encrypted {
            match self.algorithm {
                Algorithm::Rsa(ref length) | Algorithm::Dsa(ref length) => {
                    output.push_str(&format!(", {} bits", length));
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

#[derive(Debug)]
pub struct FileInfo {
    pub pem_tag: String,
    pub is_directory: bool,
    pub is_file: bool,
    pub is_pem: bool,
    pub is_readable: bool,
    pub size: Size,
    pub mode: Option<u32>,
    pub ssh_key: Option<SshKey>,
    pub path_buf: path::PathBuf,
    pub error: Option<String>,
}

impl FileInfo {
    pub fn new() -> Self {
        Self {
            error: None,
            is_directory: false,
            is_file: false,
            is_pem: false,
            is_readable: false,
            size: Size::Unknown,
            mode: None,
            path_buf: path::PathBuf::from("/"),
            pem_tag: "".to_string(),
            ssh_key: None,
        }
    }
}

impl fmt::Display for FileInfo {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        match self.ssh_key {
            Some(ref key) => {
                output.push_str(&format!("\t✓ {}", key));
                match key.algorithm {
                    Algorithm::Rsa(length) => {
                        if !key.is_encrypted && length < 2048 {
                            output.push_str("\n\t⚠️ RSA keys should be 2048 bit or larger");
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
                if !key.is_public && self.mode.unwrap_or(0o000) & 0o077 != 0o000 {
                    output.push_str("\n\t⚠️ insecure permissions");
                }
            }

            None => {
                if self.is_directory {
                    output.push_str("\t✓ is a directory");
                } else if self.is_pem {
                    output.push_str("\t⚠️ unrecognized PEM: ");
                    output.push_str(&self.pem_tag);
                    output.push_str("\n");
                } else {
                    output.push_str(&format!(
                        "\t⚠️ unrecognized {} file",
                        match self.size {
                            Size::Small => "small",
                            Size::Medium => "medium",
                            Size::Large => "large",
                            _ => "",
                        }
                    ));
                    if !self.is_readable {
                        output.push_str("\t🔥 missing read permission");
                    }
                }
            }
        }
        write!(
            out,
            "{}\n{}\n",
            self.path_buf.to_str().unwrap_or("/"),
            output
        )
    }
}

#[test]
fn test_file_info_display_encrypted_ed25519() {
    let mut file_info = FileInfo::new();
    file_info.path_buf = path::PathBuf::from("/unit-test");
    file_info.pem_tag = "OPENSSH PRIVATE KEY".to_string();
    file_info.is_file = true;
    file_info.is_pem = true;
    file_info.is_readable = true;
    file_info.size = Size::Medium;
    let mut ssh_key = SshKey::new();
    ssh_key.algorithm = Algorithm::Ed25519;
    ssh_key.is_public = false;
    ssh_key.is_encrypted = true;
    file_info.ssh_key = Some(ssh_key);
    assert_eq!(
        format!("{}", file_info),
        "/unit-test\n\t✓ private ssh key (ed25519, encrypted)\n"
    );
}

#[test]
fn test_file_info_display_encrypted_ecdsa() {
    let mut file_info = FileInfo::new();
    file_info.path_buf = path::PathBuf::from("/unit-test");
    file_info.pem_tag = "EC PRIVATE KEY".to_string();
    file_info.is_file = true;
    file_info.is_pem = true;
    file_info.is_readable = true;
    file_info.size = Size::Medium;
    let mut ssh_key = SshKey::new();
    ssh_key.algorithm = Algorithm::Ecdsa(384);
    ssh_key.is_public = false;
    ssh_key.is_encrypted = false;
    file_info.ssh_key = Some(ssh_key);
    assert_eq!(
        format!("{}", file_info),
        "/unit-test
\t✓ private ssh key (ecdsa, curve p384, not encrypted)
\t⚠️ ecdsa keys are considered insecure
"
    );
}

#[test]
fn test_file_info_display_rsa_public() {
    let mut file_info = FileInfo::new();
    file_info.path_buf = path::PathBuf::from("/unit-test");
    file_info.is_file = true;
    file_info.is_pem = true;
    file_info.is_readable = true;
    file_info.size = Size::Medium;
    let mut ssh_key = SshKey::new();
    ssh_key.algorithm = Algorithm::Rsa(2048);
    ssh_key.is_public = true;
    file_info.ssh_key = Some(ssh_key);
    assert_eq!(
        "/unit-test\n\t✓ public ssh key (rsa, 2048 bits)\n",
        format!("{}", file_info)
    );
}

#[test]
fn test_file_info_display_rsa_private_passphrase() {
    let mut file_info = FileInfo::new();
    file_info.path_buf = path::PathBuf::from("/unit-test");
    file_info.is_file = true;
    file_info.is_pem = true;
    file_info.is_readable = true;
    file_info.size = Size::Medium;
    let mut ssh_key = SshKey::new();
    ssh_key.is_encrypted = true;
    ssh_key.algorithm = Algorithm::Rsa(0);
    file_info.ssh_key = Some(ssh_key);
    assert_eq!(
        "/unit-test\n\t✓ private ssh key (rsa, encrypted)\n",
        format!("{}", file_info)
    );
}
