extern crate base64;
extern crate byteorder;
extern crate pem;
extern crate rsfs;
extern crate yasna;
mod file_info;
use byteorder::{BigEndian, ReadBytesExt};
use file_info::FileInfo3 as FileInfo;
use rsfs::{GenFS, Metadata};
use rsfs::*;
use rsfs::unix_ext::*;
use std::io;
use std::io::{ErrorKind, Read};
use std::path::{PathBuf, Path};



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

fn has_prefix(prefix: &[u8], data: &[u8]) -> bool {
    if data.len() < prefix.len() {
        return false;
    }
    return prefix == &data[0..prefix.len()];
}

fn identify_openssh_v1(bytes: Vec<u8>) -> io::Result<file_info::SshKey> {
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
    let mut ssh_key = file_info::SshKey::new();
    // Make a reader for everything after the prefix plus the null byte
    let mut reader = io::BufReader::new(&bytes[prefix.len() + 1..]);
    let cipher_name = read_field(&mut reader)?;
    let _kdfname = read_field(&mut reader);
    // kdfoptions (don't really care)
    let _kdfoptions = read_field(&mut reader);
    let _pub_key_count = reader.read_u32::<BigEndian>()?;
    let _key_length = reader.read_u32::<BigEndian>()?;
    let key_type = read_field(&mut reader)?;
    ssh_key.algorithm = match key_type.as_slice() {
        b"ssh-ed25519" => Some("ed25519".to_string()),
        b"ssh-rsa" => Some("rsa".to_string()),
        b"ssh-dss" => Some("dsa".to_string()),
        _ => None,
    };
    ssh_key.is_encrypted = match cipher_name.as_slice() {
        b"none" => false,
        _ => true,
    };
    Ok(ssh_key)
}

fn get_rsa_size(asn1_bytes: &[u8]) -> usize {
    let asn_result = yasna::parse_der(&asn1_bytes, |reader| {
        reader.read_sequence(|reader| {
            let _rsa_version = reader.next().read_i8()?;
            let modulus = reader.next().read_bigint()?;
            // We don't need anything else but yasna panics if we leave
            // unparsed data at the end of the file
            // so just read them all in
            let _pub_exp = reader.next().read_bigint()?;
            let _priv_exp = reader.next().read_bigint()?;
            let _prime1 = reader.next().read_bigint()?;
            let _prime2 = reader.next().read_bigint()?;
            let _exp1 = reader.next().read_bigint()?;
            let _exp2 = reader.next().read_bigint()?;
            let _coefficient = reader.next().read_bigint()?;
            return Ok(modulus.bits());
        })
    });
    match asn_result {
        Ok(bits) => return bits,
        Err(_) => return 0,
    }

}

fn identify_ed25519_public(content: &str) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    let mut iterator = content.splitn(3, |c: char| c.is_whitespace());
    // .collect();
    let label = iterator.next().unwrap_or("").to_string();
    let payload = iterator.next().unwrap_or(""); // base64
    ssh_key.comment = Some(iterator.next().unwrap_or("").to_string());
    let payload = base64::decode(payload).unwrap_or(vec![]); // binary
    let mut reader = io::BufReader::new(payload.as_slice());
    let algorithm = read_field(&mut reader).unwrap_or(vec![]);
    ssh_key.algorithm = Some(String::from_utf8(algorithm.clone()).unwrap_or(label));
    // let prefix = has_prefix(b"ssh-ed25519", &algorithm);
    ssh_key.point = Some(read_field(&mut reader).unwrap_or(vec![]));
    Ok(ssh_key)
}

pub fn scan<P: Permissions + PermissionsExt,
            M: Metadata<Permissions = P>,
            F: GenFS<Permissions = P, Metadata = M>>
    (fs: &F,
     path: &AsRef<Path>)
     -> io::Result<FileInfo> {

    let mut file_info = FileInfo::new();
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    file_info.path_buf = path_buf;
    let meta = fs.metadata(path)?;
    file_info.is_directory = meta.is_dir();
    file_info.is_file = meta.is_file();

    if file_info.is_file {
        let mode = meta.permissions().mode();
        // https://www.cyberciti.biz/faq/unix-linux-bsd-chmod-numeric-permissions-notation-command/
        file_info.is_readable = mode & 0o444 != 0;
    }
    if file_info.is_readable {
        match meta.len() {
            0...50 => {
                file_info.is_size_small = true;
            }
            51...4096 => {
                file_info.is_size_medium = true;
            }
            _ => {
                file_info.is_size_large = true;
            }
        }
    }
    if file_info.is_size_medium {
        let mut content = String::new();
        let mut file = fs.open_file(path)?;
        file.read_to_string(&mut content)?;
        if content.starts_with("ssh-ed25519 ") {
            file_info.ssh_key = Some(identify_ed25519_public(&content)?);
        }
        if content.starts_with("ssh-rsa ") {
            let mut ssh_key = file_info::SshKey::new();
            ssh_key.is_public = true;
            ssh_key.algorithm = Some("rsa".to_string());
            file_info.ssh_key = Some(ssh_key);
        }
        if content.starts_with("ssh-dss ") {
            let mut ssh_key = file_info::SshKey::new();
            ssh_key.is_public = true;
            ssh_key.algorithm = Some("dsa".to_string());
            file_info.ssh_key = Some(ssh_key);
        }
        if content.starts_with("ecdsa-sha2-nistp256 ") {
            let mut ssh_key = file_info::SshKey::new();
            ssh_key.is_public = true;
            ssh_key.algorithm = Some("ecdsa".to_string());
            file_info.ssh_key = Some(ssh_key);
        }
        let parsed_result = pem::parse(content);
        match parsed_result {
            Ok(pem) => {
                file_info.is_pem = true;
                file_info.pem_tag = pem.tag.to_string();
                match pem.tag.as_str() {
                    "OPENSSH PRIVATE KEY" => {
                        // file_info.algorithm = "ed25519".to_string();
                        // file_info.is_private_key = true;
                        if has_prefix(b"openssh-key-v1", &pem.contents) {
                            file_info.ssh_key = Some(identify_openssh_v1(pem.contents)?);
                            // file_info.is_encrypted = details.encrypted;
                            // match details.algorithm {
                            //     Some(name) => file_info.algorithm = name.to_string(),
                            //     _ => (),
                            // }
                        }
                    }
                    "RSA PRIVATE KEY" => {
                        let mut ssh_key = file_info::SshKey::new();
                        ssh_key.is_public = false;
                        ssh_key.algorithm = Some("rsa".to_string());
                        ssh_key.key_length = Some(get_rsa_size(&pem.contents));
                        file_info.ssh_key = Some(ssh_key);
                    }
                    "EC PRIVATE KEY" => {
                        let mut ssh_key = file_info::SshKey::new();
                        ssh_key.is_public = false;
                        ssh_key.algorithm = Some("ecdsa".to_string());
                        file_info.ssh_key = Some(ssh_key);
                    }
                    "DSA PRIVATE KEY" => {
                        let mut ssh_key = file_info::SshKey::new();
                        ssh_key.is_public = false;
                        ssh_key.algorithm = Some("dsa".to_string());
                        file_info.ssh_key = Some(ssh_key);
                    }
                    "ENCRYPTED PRIVATE KEY" => {
                        let mut ssh_key = file_info::SshKey::new();
                        ssh_key.is_public = false;
                        ssh_key.is_encrypted = true;
                        file_info.ssh_key = Some(ssh_key);
                    }
                    _ => (),
                }
            }
            _ => (),
        }
    }

    let mut path_buf = PathBuf::new();
    path_buf.push(path);

    Ok(file_info)
}
