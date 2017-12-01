extern crate byteorder;
extern crate pem;
extern crate rsfs;
mod file_info;
use byteorder::{BigEndian, ReadBytesExt};
use file_info::FileInfo;
use rsfs::{GenFS, Metadata};
use rsfs::*;
use rsfs::unix_ext::*;
use std::io;
use std::io::{ErrorKind,Read};
use std::path::{PathBuf, Path};

struct PrivateKey {
    algorithm: Option<&'static str>,
    encrypted: bool,
}

fn bail(message: String) -> io::Error {
    return io::Error::new(ErrorKind::Other, message);
}

/// Read a length-prefixed field in the format openssh uses
/// which is a 4-byte big-endian u32 length
/// followed by that many bytes of payload
fn read_field<R: ReadBytesExt + Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = reader.read_u32::<BigEndian>()?;
    if len > 4096 {
        return Err(bail("Field size too large. File possibly corrupt.".to_string()));
    }
    let mut word = vec![0u8;len as usize];
    reader.read_exact(&mut word.as_mut_slice())?;
    Ok(word)
}

fn identify_openssh_v1(bytes: Vec<u8>) -> io::Result<PrivateKey> {
    /*
    byte[]	AUTH_MAGIC
    string	ciphername
    string	kdfname
    string	kdfoptions
    int	number of keys N
    string	publickey1
    string	publickey2
    */

    let prefix = b"openssh-key-v1";
    // Make a reader for everything after the prefix plus the null byte
    let mut reader = io::BufReader::new(&bytes[prefix.len() + 1..]);
    let cipher_name = read_field(&mut reader)?;
    let _kdfname = read_field(&mut reader);
    // kdfoptions (don't really care)
    let _kdfoptions = read_field(&mut reader);
    let _pub_key_count = reader.read_u32::<BigEndian>()?;
    let _key_length = reader.read_u32::<BigEndian>()?;
    let key_type = read_field(&mut reader)?;
    let algorithm = match key_type.as_slice() {
        b"ssh-ed25519" => Some("ed25519"),
        b"ssh-rsa" => Some("rsa"),
        b"ssh-dss" => Some("dsa"),
        _ => None,
    };
    let encrypted = match cipher_name.as_slice() {
        b"none" => false,
        _ => true,
    };
    Ok(PrivateKey {
           algorithm,
           encrypted,
       })
}

pub fn scan<P: Permissions + PermissionsExt,
            M: Metadata<Permissions = P>,
            F: GenFS<Permissions = P, Metadata = M>>
    (fs: &F,
     path: &AsRef<Path>)
     -> io::Result<FileInfo> {
    println!("HEY scan starting");

    let meta = fs.metadata(path)?;
    let is_directory = meta.is_dir();
    let is_file = meta.is_file();
    let mut is_encrypted = false;
    let mut is_pem = false;
    let mut is_private_key = false;
    let mut is_public_key = false;
    let mut is_readable = false;
    let mut is_size_large = false;
    let mut is_size_medium = false;
    let mut is_size_small = false;
    let mut algorithm = "unknown";
    let mut pem_tag = "".to_string();
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
            algorithm = "ecdsa";
            is_public_key = true;
        }
        if content.starts_with("ssh-rsa ") {
            algorithm = "rsa";
            is_public_key = true;
        }
        if content.starts_with("ssh-dss ") {
            algorithm = "dsa";
            is_public_key = true;
        }
        if content.starts_with("ecdsa-sha2-nistp256 ") {
            algorithm = "ecdsa";
            is_public_key = true;
        }
        println!("HEY about to parse");
        let parsed_result = pem::parse(content);
        match parsed_result {
            Ok(pem) => {
                println!("HEY parsed pem {}", pem.tag);
                is_pem = true;
                pem_tag = pem.tag.to_string();
                match pem.tag.as_str() {
                    "OPENSSH PRIVATE KEY" => {
                        algorithm = "ed25519";
                        is_private_key = true;
                        let prefix = b"openssh-key-v1";
                        let mut has_prefix = false;
                        if pem.contents.len() >= prefix.len() {
                            has_prefix = prefix == &pem.contents[0..prefix.len()];
                        }
                        if has_prefix {
                            let details = identify_openssh_v1(pem.contents)?;
                            is_encrypted = details.encrypted;
                            match details.algorithm {
                                Some(name) => algorithm = name,
                                _ => (),
                            }
                        }
                    }
                    "RSA PRIVATE KEY" => {
                        algorithm = "rsa";
                        is_private_key = true;
                    }
                    "EC PRIVATE KEY" => {
                        is_private_key = true;
                        algorithm = "ecdsa";
                    }
                    "DSA PRIVATE KEY" => {
                        algorithm = "dsa";
                        is_private_key = true;
                    }
                    _ => (),
                }
            }
            _ => (),
        }
    }

    let mut path_buf = PathBuf::new();
    path_buf.push(path);

    Ok(FileInfo {
           algorithm: algorithm.to_string(),
           is_directory,
           is_encrypted,
           is_file,
           is_pem,
           is_private_key,
           is_public_key,
           is_readable,
           is_size_large,
           is_size_medium,
           is_size_small,
           is_ssh_key,
           path_buf,
           pem_tag,
       })
}
