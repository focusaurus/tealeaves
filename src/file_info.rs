use std::{fmt, path};

pub struct FileInfo {
    pub algorithm: String,
    pub pem_tag: String,
    pub is_directory: bool,
    pub is_encrypted: bool,
    pub is_file: bool,
    pub is_pem: bool,
    pub is_private_key: bool,
    pub is_public_key: bool,
    pub is_readable: bool,
    pub is_size_large: bool,
    pub is_size_medium: bool,
    pub is_size_small: bool,
    pub is_ssh_key: bool,
    pub rsa_size: usize,
    pub ed25519_point: Option<[u8; 64]>,
    pub path_buf: path::PathBuf,
}

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
            output.push_str(", ");
        }
        if self.is_encrypted {
            output.push_str("encrypted");
        } else {
            output.push_str("not encrypted");
        }
        if self.key_length.is_some() {
            output.push_str(&format!(", {} bits", self.key_length.unwrap()));
        }
        output.push_str(")");
        write!(out, "{}", output)
    }
}

pub struct FileInfo3 {
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
}

impl FileInfo3 {
    pub fn new() -> Self {
        Self {
            is_directory: false,
            is_file: false,
            is_pem: false,
            is_readable: false,
            is_size_large: false,
            is_size_medium: false,
            is_size_small: false,
            ssh_key: None,
            path_buf: path::PathBuf::from("/"),
            pem_tag: "".to_string(),
        }
    }
}

impl fmt::Display for FileInfo3 {
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
        write!(out, "{}\n{}", self.path_buf.to_str().unwrap_or("/"), output)
    }
}
/*
#[test]
fn test_file_info_display_encrypted_ed25519() {
    let mut file_info = FileInfo::new();
    file_info.algorithm = "ed25519".to_string();
    file_info.pem_tag = "OPENSSH PRIVATE KEY".to_string();
    file_info.is_encrypted = true;
    file_info.is_file = true;
    file_info.is_pem = true;
    file_info.is_private_key = true;
    file_info.is_readable = true;
    file_info.is_size_medium = true;
    file_info.is_ssh_key = true;
    file_info.path_buf = path::PathBuf::from("/unit-test");
    assert_eq!(format!("{}", file_info),
               "/unit-test\n\t✓ private ssh key (ed25519, encrypted)\n");
}

#[test]
fn test_file_info_display_rsa_public() {
    let mut file_info = FileInfo::new();
    file_info.algorithm = "rsa".to_string();
    file_info.is_file = true;
    file_info.is_pem = true;
    file_info.is_public_key = true;
    file_info.is_readable = true;
    file_info.is_size_medium = true;
    file_info.is_ssh_key = true;
    file_info.path_buf = path::PathBuf::from("/unit-test");
    assert_eq!(format!("{}", file_info),
               "/unit-test\n\t✓ public ssh key (rsa)\n");
}
*/
