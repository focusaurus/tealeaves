use std::{fmt, path};

#[derive(Debug)]
pub struct SshKey {
    pub algorithm: Option<String>,
    pub comment: Option<String>,
    pub is_encrypted: bool,
    pub is_public: bool,
    pub key_length: Option<usize>,
    pub point: Option<Vec<u8>>,
}

impl SshKey {
    pub fn new() -> Self {
        Self {
            algorithm: None,
            comment: None,
            is_encrypted: false,
            is_public: false,
            key_length: None,
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
        if self.algorithm.is_some() {
            output.push_str(self.algorithm.as_ref().unwrap());
        }
        if self.key_length.is_some() {
            output.push_str(&format!(", {} bits", self.key_length.unwrap()));
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
    pub is_size_large: bool,
    pub is_size_medium: bool,
    pub is_size_small: bool,
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
            is_size_large: false,
            is_size_medium: false,
            is_size_small: false,
            path_buf: path::PathBuf::from("/"),
            pem_tag: "".to_string(),
            ssh_key: None,
        }
    }
}

impl fmt::Display for FileInfo {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        if self.is_directory {
            output.push_str("\t✓ is a directory\n");
        } else if self.ssh_key.is_some() {
            output.push_str(&format!("\t✓ {}", self.ssh_key.as_ref().unwrap()));
        } else if self.is_pem {
            output.push_str("\t⚠️ unrecognized PEM: ");
            output.push_str(&self.pem_tag);
            output.push_str("\n");
        } else if self.is_size_small {
            output.push_str("\t⚠️ unrecognized small file\n");
        } else if self.is_size_large {
            output.push_str("\t⚠️ unrecognized large file\n");
        } else if !self.is_readable {
            output.push_str("\t🔥 missing read permission\n");
        }
        write!(out,
               "{}\n{}\n",
               self.path_buf.to_str().unwrap_or("/"),
               output)
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
    file_info.is_size_medium = true;
    let mut ssh_key = SshKey::new();
    ssh_key.algorithm = Some("ed25519".to_string());
    ssh_key.is_public = false;
    ssh_key.is_encrypted = true;
    file_info.ssh_key = Some(ssh_key);
    assert_eq!(format!("{}", file_info),
               "/unit-test\n\t✓ private ssh key (ed25519, encrypted)\n");
}
#[test]
fn test_file_info_display_encrypted_ecdsa() {
    let mut file_info = FileInfo::new();
    file_info.path_buf = path::PathBuf::from("/unit-test");
    file_info.pem_tag = "EC PRIVATE KEY".to_string();
    file_info.is_file = true;
    file_info.is_pem = true;
    file_info.is_readable = true;
    file_info.is_size_medium = true;
    let mut ssh_key = SshKey::new();
    ssh_key.algorithm = Some("ecdsa".to_string());
    ssh_key.is_public = false;
    ssh_key.is_encrypted = false;
    ssh_key.key_length = Some(384);
    file_info.ssh_key = Some(ssh_key);
    assert_eq!(format!("{}", file_info),
               "/unit-test\n\t✓ private ssh key (ecdsa, 384 bits, not encrypted)\n");
}

#[test]
fn test_file_info_display_rsa_public() {
    let mut file_info = FileInfo::new();
    file_info.path_buf = path::PathBuf::from("/unit-test");
    file_info.is_file = true;
    file_info.is_pem = true;
    file_info.is_readable = true;
    file_info.is_size_medium = true;
    let mut ssh_key = SshKey::new();
    ssh_key.algorithm = Some("rsa".to_string());
    ssh_key.is_public = true;
    ssh_key.key_length = Some(2048);
    file_info.ssh_key = Some(ssh_key);
    assert_eq!("/unit-test\n\t✓ public ssh key (rsa, 2048 bits)\n",
               format!("{}", file_info));
}
