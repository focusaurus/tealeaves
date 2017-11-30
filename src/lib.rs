extern crate rsfs;
extern crate pem;
mod level;
pub mod check;
pub use check::Check;
pub use level::Level;
use rsfs::{GenFS, Metadata};
use rsfs::*;
use rsfs::unix_ext::*;
use std::{io, path, fmt};
use std::path::{PathBuf, Path};
use std::io::Read;

#[derive(Debug)]
pub struct FileInfo {
    pub path_buf: path::PathBuf,
    pub checks: Vec<Check>,
}

impl FileInfo {
    pub fn new(path_buf: PathBuf, checks: Vec<Check>) -> Self {
        FileInfo { path_buf, checks }
    }
}

impl fmt::Display for FileInfo {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        let mut checks = self.checks.to_vec();
        checks.sort();
        for check in checks {
            output.push_str(&format!("\t {}\n", check));
        }
        write!(out, "{}\n{}", self.path_buf.to_str().unwrap(), output)
    }
}

#[derive(Debug)]
pub struct FileInfo2 {
    pub is_directory: bool,
    pub is_dsa: bool,
    pub is_ecdsa: bool,
    pub is_ed25519: bool,
    pub is_encrypted: bool,
    pub is_file: bool,
    pub is_pem: bool,
    pub is_private_key: bool,
    pub is_public_key: bool,
    pub is_readable: bool,
    pub is_rsa: bool,
    pub is_size_large: bool,
    pub is_size_medium: bool,
    pub is_size_small: bool,
    pub is_ssh_key: bool,
    pub path_buf: path::PathBuf,
}

impl FileInfo2 {
    fn algorithm(&self) -> &str {
        if self.is_dsa {
            return "dsa";
        }
        if self.is_rsa {
            return "rsa";
        }
        if self.is_ecdsa {
            return "ecdsa";
        }
        if self.is_ed25519 {
            return "ed25519";
        }
        return "unknown";
    }
}

impl fmt::Display for FileInfo2 {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        if self.is_directory {
            output.push_str("\t✓ is a directory\n");
        } else if self.is_private_key {
            output.push_str("\t✓ private ssh key (");
            output.push_str(self.algorithm());
            output.push_str(")\n");
            if self.is_encrypted {
                output.push_str("\t✓ is encrypted");
            }
        } else if self.is_public_key {
            output.push_str("\t✓ public ssh key (");
            output.push_str(self.algorithm());
            output.push_str(")\n");
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

pub fn scan4<P: Permissions + PermissionsExt,
             M: Metadata<Permissions = P>,
             F: GenFS<Permissions = P, Metadata = M>>
    (fs: &F,
     path: &AsRef<Path>)
     -> io::Result<FileInfo2> {

    let meta = fs.metadata(path)?;
    let is_directory = meta.is_dir();
    let is_file = meta.is_file();
    let mut is_dsa = false;
    let mut is_ecdsa = false;
    let mut is_ed25519 = false;
    let mut is_encrypted = false;
    let mut is_pem = false;
    let mut is_private_key = false;
    let mut is_public_key = false;
    let mut is_readable = false;
    let mut is_rsa = false;
    let mut is_size_large = false;
    let mut is_size_medium = false;
    let mut is_size_small = false;
    let is_ssh_key = false;
    if is_file {
        let mode = meta.permissions().mode();
        // https://www.cyberciti.biz/faq/unix-linux-bsd-chmod-numeric-permissions-notation-command/
        is_readable = mode & 0o444 != 0;
    }
    if is_readable {
        match meta.len() {
            0...50 => {
                is_size_small = true;
            }
            51...4096 => {
                is_size_medium = true;
            }
            _ => {
                is_size_large = true;
            }
        }
    }
    if is_size_medium {
        let mut content = String::new();
        let mut file = fs.open_file(path)?;
        file.read_to_string(&mut content)?;
        if content.starts_with("ssh-ed25519 ") {
            is_public_key = true;
            is_ed25519 = true;
        }
        if content.starts_with("ssh-rsa ") {
            is_public_key = true;
            is_rsa = true;
        }
        if content.starts_with("ssh-dss ") {
            is_public_key = true;
            is_dsa = true;
        }
        if content.starts_with("ecdsa-sha2-nistp256 ") {
            is_public_key = true;
            is_ecdsa = true;
        }
        let parsed_result = pem::parse(content);
        match parsed_result {
            Ok(pem) => {
                is_pem = true;
                let prefix = b"openssh-key-v1";
                if pem.contents.len() >= prefix.len() {
                    is_private_key = prefix == &pem.contents[0..prefix.len()];
                }
                let mut fields = pem.contents[prefix.len() - 1..].split(|&byte| byte == 0);
                let cipher_name = fields.next().unwrap_or(b"UNKNOWN");
                println!("@bug {:?}", String::from_utf8_lossy(cipher_name));
                if cipher_name != b"none" && cipher_name != b"UNKNOWN" {
                    is_encrypted = true;
                }
                /*                	byte[]	AUTH_MAGIC
	string	ciphername
	string	kdfname
	string	kdfoptions
	int	number of keys N
	string	publickey1
	string	publickey2
*/

                // if !is_private_key {
                //     println!("HEY {}: {}",
                //              &path.display(),
                //              String::from_utf8_lossy(&pem.contents[0..100]));
                // }
            }
            _ => (),
        }
    }

    let mut path_buf = PathBuf::new();
    path_buf.push(path);

    Ok(FileInfo2 {
           is_directory,
           is_dsa,
           is_ecdsa,
           is_ed25519,
           is_encrypted,
           is_file,
           is_pem,
           is_private_key,
           is_public_key,
           is_readable,
           is_rsa,
           is_size_large,
           is_size_medium,
           is_size_small,
           is_ssh_key,
           path_buf,
       })
}

pub fn scan<P: Permissions + PermissionsExt,
            M: Metadata<Permissions = P>,
            F: GenFS<Permissions = P, Metadata = M>>
    (fs: &F,
     path: &AsRef<Path>)
     -> io::Result<FileInfo> {
    let mut checks: Vec<Check> = vec![];
    let meta = fs.metadata(path)?;
    if meta.is_dir() {
        checks.push(Check::directory());
    }
    if meta.is_file() {
        let mode = meta.permissions().mode();
        // https://www.cyberciti.biz/faq/unix-linux-bsd-chmod-numeric-permissions-notation-command/
        let can_read = mode & 0o444 != 0;
        if meta.is_empty() {
            checks.push(Check::empty());
        }
        if can_read {
            match meta.len() {
                0...50 => checks.push(Check::too_small()),
                51...4096 => {
                    let mut content = String::new();
                    let mut file = fs.open_file(path)?;
                    file.read_to_string(&mut content)?;
                    if content.starts_with("ssh-ed25519 ") {
                        checks.push(Check::public_key_ed25519());
                    }
                    if content.starts_with("ssh-rsa ") {
                        checks.push(Check::public_key_rsa());
                    }
                    let parsed_result = pem::parse(content);
                    match parsed_result {
                        Ok(_) => checks.push(Check::pem()),
                        _ => checks.push(Check::not_pem()),
                    }
                }
                _ => checks.push(Check::too_big()),
            }
        } else {
            checks.push(Check::unreadable());
        }
    }
    let mut path_buf = PathBuf::new();
    path_buf.push(path);

    Ok(FileInfo { path_buf, checks })
}
