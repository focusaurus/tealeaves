extern crate base64;
extern crate byteorder;
extern crate pem;
extern crate rsfs;
extern crate yasna;
mod file_info;
use byteorder::{BigEndian, ReadBytesExt};
use file_info::FileInfo;
use rsfs::{GenFS, Metadata};
use rsfs::*;
use rsfs::unix_ext::*;
use std::io;
use std::io::{ErrorKind, Read};
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

fn has_prefix(prefix: &[u8], data: &[u8]) -> bool {
    if data.len() < prefix.len() {
        return false;
    }
    return prefix == &data[0..prefix.len()];
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

fn validate_ed25519(content: &str) -> Result<(), String> {
    // let mut iterator = content.split_whitespace();
    let mut iterator = content.splitn(3, |c: char| c.is_whitespace());
    // .collect();

    let label = iterator.next().unwrap_or("");
    println!("label {}", label);
    let payload = iterator.next().unwrap_or(""); // base64
    let comment = iterator.next().unwrap_or("");
    println!("comment {}", comment);
    let payload = base64::decode(payload).unwrap_or(vec![]); // binary
    let mut reader = io::BufReader::new(payload.as_slice());
    let algorithm = read_field(&mut reader).unwrap_or(vec![]);
    println!("algorithm {}", String::from_utf8_lossy(&algorithm));
    let prefix = has_prefix(b"ssh-ed25519", &algorithm);
    println!("prefix {}", prefix);
    let payload = read_field(&mut reader).unwrap_or(vec![]);
    for byte in payload {
        print!("{:x}", &byte);
    }
    Ok(())
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
            file_info.algorithm = "ed25519".to_string();
            file_info.is_public_key = true;
            match validate_ed25519(&content) {
                Err(error) => {
                    println!("ed25519 errors {:?}", error);
                }
                _ => (),
            }
        }
        if content.starts_with("ssh-rsa ") {
            file_info.algorithm = "rsa".to_string();
            file_info.is_public_key = true;
        }
        if content.starts_with("ssh-dss ") {
            file_info.algorithm = "dsa".to_string();
            file_info.is_public_key = true;
        }
        if content.starts_with("ecdsa-sha2-nistp256 ") {
            file_info.algorithm = "ecdsa".to_string();
            file_info.is_public_key = true;
        }
        let parsed_result = pem::parse(content);
        match parsed_result {
            Ok(pem) => {
                file_info.is_pem = true;
                file_info.pem_tag = pem.tag.to_string();
                match pem.tag.as_str() {
                    "OPENSSH PRIVATE KEY" => {
                        file_info.algorithm = "ed25519".to_string();
                        file_info.is_private_key = true;
                        if has_prefix(b"openssh-key-v1", &pem.contents) {
                            let details = identify_openssh_v1(pem.contents)?;
                            file_info.is_encrypted = details.encrypted;
                            match details.algorithm {
                                Some(name) => file_info.algorithm = name.to_string(),
                                _ => (),
                            }
                        }
                    }
                    "RSA PRIVATE KEY" => {
                        file_info.algorithm = "rsa".to_string();
                        file_info.is_private_key = true;
                        file_info.rsa_size = get_rsa_size(&pem.contents);

                    }
                    "EC PRIVATE KEY" => {
                        file_info.is_private_key = true;
                        file_info.algorithm = "ecdsa".to_string();
                    }
                    "DSA PRIVATE KEY" => {
                        file_info.algorithm = "dsa".to_string();
                        file_info.is_private_key = true;
                    }
                    "ENCRYPTED PRIVATE KEY" => {
                        file_info.is_encrypted = true;
                        file_info.is_private_key = true;
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
