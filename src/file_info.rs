use std::{fmt,path};

#[derive(Debug)]
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
    pub path_buf: path::PathBuf,
}

impl fmt::Display for FileInfo {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        if self.is_directory {
            output.push_str("\t✓ is a directory\n");
        } else if self.is_private_key {
            output.push_str("\t✓ private ssh key (");
            output.push_str(&self.algorithm);
            output.push_str(", ");
            if self.is_encrypted {
                output.push_str("encrypted)\n");
            } else {
                output.push_str("not encrypted)\n");
            }
        } else if self.is_public_key {
            output.push_str("\t✓ public ssh key (");
            output.push_str(&self.algorithm);
            output.push_str(")\n");
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
        write!(out, "{}\n{}", self.path_buf.to_str().unwrap(), output)
    }
}

#[test]
fn test_file_info_display() {
    let file_info = FileInfo {
            algorithm: "ed25519".to_string(),
            pem_tag: "OPENSSH PRIVATE KEY".to_string(),
            is_directory: false,
            is_encrypted: true,
            is_file: true,
            is_pem: true,
            is_private_key: true,
            is_public_key: false,
            is_readable: true,
            is_size_large: false,
            is_size_medium: true,
            is_size_small: false,
            is_ssh_key: true,
            path_buf: path::PathBuf::from("/unit-test"),
    };
    assert_eq!(format!("{}", file_info), "/unit-test\n\t✓ private ssh key (ed25519, encrypted)\n");
    let file_info = FileInfo {
            algorithm: "rsa".to_string(),
            pem_tag: "".to_string(),
            is_directory: false,
            is_encrypted: false,
            is_file: true,
            is_pem: true,
            is_private_key: false,
            is_public_key: true,
            is_readable: true,
            is_size_large: false,
            is_size_medium: true,
            is_size_small: false,
            is_ssh_key: true,
            path_buf: path::PathBuf::from("/unit-test"),
    };
    assert_eq!(format!("{}", file_info), "/unit-test\n\t✓ public ssh key (rsa)\n");
}
