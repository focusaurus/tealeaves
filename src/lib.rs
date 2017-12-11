extern crate base64;
extern crate byteorder;
extern crate nom_pem;
extern crate rsfs;
extern crate yasna;
mod file_info;
mod parse;
use byteorder::{BigEndian, ReadBytesExt};
use file_info::FileInfo;
use nom_pem::headers::{HeaderEntry, ProcTypeType};
use rsfs::{GenFS, Metadata};
use rsfs::*;
use rsfs::unix_ext::*;
use std::error::Error;
use std::io;
use std::io::{ErrorKind, Read};
use std::path::{PathBuf, Path};

#[macro_use]
extern crate nom;


fn bail(message: String) -> io::Error {
    return io::Error::new(ErrorKind::Other, message);
}

fn is_encrypted(headers: &Vec<HeaderEntry>) -> bool {
    headers
        .iter()
        .any(|header| match header {
                 &HeaderEntry::ProcType(_code, ref kind) => kind == &ProcTypeType::ENCRYPTED,
                 _ => false,
             })
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

#[test]
fn test_has_prefix() {
    assert!(has_prefix(b"", b""));
    assert!(has_prefix(b"", b" abc "));
    assert!(has_prefix(b"a", b"a"));
    assert!(has_prefix(b"a", b"ab"));

    // negative tests
    assert!(!has_prefix(b"ab", b"ba"));
    assert!(!has_prefix(b"cat", b"dog"));
    assert!(!has_prefix(b"cat", b"dogcat"));
}

fn identify_openssh_v1(bytes: &[u8]) -> io::Result<file_info::SshKey> {
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

fn get_rsa_length(asn1_bytes: &[u8]) -> usize {
    let asn_result = yasna::parse_der(&asn1_bytes, |reader| {
        reader.read_sequence(|reader| {
            let _rsa_version = reader.next().read_i8()?;
            let modulus = reader.next().read_bigint()?;
            // We don't need anything else but yasna panics if we leave
            // unparsed data at the end of the file
            // so just read them all in
            // For the record they are
            // _pub_exp
            // _priv_exp
            // _prime1
            // _prime2
            // _exp1
            // _exp2
            // _coefficient
            for _ in 0..7 {
                let _int = reader.next().read_bigint()?;
            }
            return Ok(modulus.bits());
        })
    });
    match asn_result {
        Ok(bits) => return bits,
        Err(_) => return 0,
    }
}

fn get_dsa_length(asn1_bytes: &[u8]) -> usize {
    let asn_result = yasna::parse_der(&asn1_bytes, |reader| {
        reader.read_sequence(|reader| {
            let _int1 = reader.next().read_i8()?;
            let int2 = reader.next().read_bigint()?;
            // We don't need anything else but yasna panics if we leave
            // unparsed data at the end of the file
            // so just read them all in
            for _ in 0..4 {
                let _int = reader.next().read_bigint()?;
            }
            return Ok(int2.bits());
        })
    });
    // FIXME yasna::ASN1Error handling
    match asn_result {
        Ok(bits) => return bits,
        Err(error) => {
            //print!("ERROR {}", error);
            return 0;
        }
    }
}

fn get_ecdsa_length(asn1_bytes: &[u8]) -> Result<usize, String> {
    let asn_result = yasna::parse_der(&asn1_bytes, |reader| {
        reader.read_sequence(|reader| {
            let _ = reader.next().read_i8()?;
            let _ = reader.next().read_bytes()?;
            let oid = reader
                .next()
                .read_tagged(yasna::Tag::context(0), |reader| reader.read_oid())
                .unwrap();
            let _discard = reader
                .next()
                .read_tagged(yasna::Tag::context(1), |reader| reader.read_bitvec());

            if &oid.components().as_slice() == &[1u64, 2, 840, 10045, 3, 1, 7] {
                return Ok(256);
            }
            if &oid.components().as_slice() == &[1u64, 3, 132, 0, 34] {
                return Ok(384);
            }
            if &oid.components().as_slice() == &[1u64, 3, 132, 0, 35] {
                return Ok(521);
            }

            return Ok(0);
        })
    });
    match asn_result {
        Ok(0) => return Err("Unrecognized ecdsa curve".to_string()),
        Ok(bits) => return Ok(bits),
        Err(error) => {
            return Err(error.description().to_string());
        }
    }
}
fn identify_ed25519_public1(content: &str) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    let mut iterator = content.splitn(3, |c: char| c.is_whitespace());
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

fn identify_ed25519_public(bytes: &[u8]) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    let pub_key = parse::public_key(bytes)?;
    let comment = String::from_utf8(Vec::from(pub_key.comment)).unwrap();
    ssh_key.comment = Some(comment);
    if let Some(payload) = pub_key.payload {
        let mut reader = io::BufReader::new(payload.as_slice());

        let algorithm = read_field(&mut reader).unwrap_or(vec![]);
        ssh_key.point = Some(read_field(&mut reader).unwrap_or(vec![]));
        if let Ok(algo) = String::from_utf8(algorithm.clone()) {
            ssh_key.algorithm = Some(algo);
        }
        if has_prefix(b"ssh-ed25519", pub_key.algorithm) {
            ssh_key.algorithm = Some("ed25519".to_string());
        }
    }
    Ok(ssh_key)
}

fn identify_rsa_public(bytes: &[u8]) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    let pub_key = parse::public_key(bytes)?;
    if pub_key.algorithm == &b"ssh-rsa"[..] {
        ssh_key.algorithm = Some("rsa".to_string());
    }
    let comment = String::from_utf8(Vec::from(pub_key.comment)).unwrap();
    ssh_key.comment = Some(comment);
    if let Some(payload) = pub_key.payload {
        let mut reader = io::BufReader::new(payload.as_slice());
        let algorithm = read_field(&mut reader).unwrap_or(vec![]);
        let _exponent = read_field(&mut reader).unwrap_or(vec![]);
        let modulus = read_field(&mut reader).unwrap_or(vec![]);
        // modulus has a leading zero byte to be discarded, then just convert bytes to bits
        ssh_key.key_length = Some((modulus.len() - 1) * 8);
        if let Ok(algo) = String::from_utf8(algorithm.clone()) {
            ssh_key.algorithm = Some(algo);
        }
    }
    Ok(ssh_key)
}

fn identify_dsa_public(content: &str) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    let mut iterator = content.splitn(3, |c: char| c.is_whitespace());
    let label = iterator.next().unwrap_or("").to_string();
    let payload = iterator.next().unwrap_or(""); // base64
    ssh_key.comment = Some(iterator.next().unwrap_or("").to_string());
    println!("HEY {:?} {} {:?}", label, payload.len(), ssh_key.comment);
    let payload = base64::decode(payload).unwrap_or(vec![]); // binary
    let mut reader = io::BufReader::new(payload.as_slice());
    let algorithm = read_field(&mut reader).unwrap_or(vec![]);
    ssh_key.algorithm = if has_prefix(&algorithm, b"ssh-dss ") {
        Some("dsa".to_string())
    } else {
        Some(label)
    };
    println!("HEY DSA 3 {:?}", ssh_key.comment);

    let field = read_field(&mut reader).unwrap_or(vec![]);
    // field has a leading zero byte to be discarded, then just convert bytes to bits
    ssh_key.key_length = Some((field.len() - 1) * 8);
    Ok(ssh_key)
}

fn identify_ecdsa_public(content: &str) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    let mut iterator = content.splitn(3, |c: char| c.is_whitespace());
    let label = iterator.next().unwrap_or("").to_string();
    let payload = iterator.next().unwrap_or(""); // base64
    ssh_key.comment = Some(iterator.next().unwrap_or("").to_string());
    let payload = base64::decode(payload).unwrap_or(vec![]); // binary
    let mut reader = io::BufReader::new(payload.as_slice());
    let algorithm = read_field(&mut reader).unwrap_or(vec![]);
    let algorithm = String::from_utf8(algorithm.clone()).unwrap_or(label);
    if algorithm.starts_with("ecdsa") {
        ssh_key.algorithm = Some("ecdsa".to_string());
    }
    if algorithm.ends_with("-nistp256") {
        ssh_key.key_length = Some(256);
    }
    if algorithm.ends_with("-nistp384") {
        ssh_key.key_length = Some(384);
    }
    if algorithm.ends_with("-nistp521") {
        ssh_key.key_length = Some(521);
    }
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
        let content = String::new();
        let mut file = fs.open_file(path)?;
        let mut bytes = vec![];
        file.read_to_end(&mut bytes).unwrap();
        if bytes.starts_with(b"ssh-ed25519 ") {
            file_info.ssh_key = Some(identify_ed25519_public(&bytes)?);
        }
        if bytes.starts_with(b"ssh-rsa ") {
            file_info.ssh_key = Some(identify_rsa_public(&bytes)?);
        }
        if bytes.starts_with(b"ssh-dss ") {
            file_info.ssh_key = Some(identify_dsa_public(&content)?);
        }
        if bytes.starts_with(b"ecdsa-") {
            file_info.ssh_key = Some(identify_ecdsa_public(&content)?);
        }
        if bytes.starts_with(b"-----BEGIN ") {
            match nom_pem::decode_block(&bytes) {
                Ok(block) => {
                    println!("PEM OK {}", block.data.len());
                    file_info.is_pem = true;
                    file_info.pem_tag = block.block_type.to_string();

                    match block.block_type {
                        "DSA PRIVATE KEY" => {
                            let mut ssh_key = file_info::SshKey::new();
                            ssh_key.is_public = false;
                            ssh_key.algorithm = Some("dsa".to_string());
                            ssh_key.is_encrypted = is_encrypted(&block.headers);
                            if !ssh_key.is_encrypted {
                                ssh_key.key_length = Some(get_dsa_length(&block.data));
                            }
                            file_info.ssh_key = Some(ssh_key);

                        }
                        "OPENSSH PRIVATE KEY" => {
                            if has_prefix(&block.data, b"openssh-key-v1") {
                                file_info.ssh_key = Some(identify_openssh_v1(&block.data)?);
                            }
                        }
                        "RSA PRIVATE KEY" => {
                            let mut ssh_key = file_info::SshKey::new();
                            ssh_key.is_public = false;
                            ssh_key.algorithm = Some("rsa".to_string());
                            ssh_key.key_length = Some(get_rsa_length(&block.data));
                            file_info.ssh_key = Some(ssh_key);
                        }
                        "EC PRIVATE KEY" => {
                            let mut ssh_key = file_info::SshKey::new();
                            ssh_key.is_public = false;
                            ssh_key.algorithm = Some("ecdsa".to_string());
                            let result = get_ecdsa_length(&block.data);
                            if result.is_err() {
                                // FIXME attach err to ssh_key struct for later printing
                            }
                            ssh_key.key_length = result.ok();
                            file_info.ssh_key = Some(ssh_key);
                        }
                        "ENCRYPTED PRIVATE KEY" => {
                            let mut ssh_key = file_info::SshKey::new();
                            ssh_key.is_public = false;
                            ssh_key.is_encrypted = true;
                            file_info.ssh_key = Some(ssh_key);
                        }
                        _ => {}
                    }
                }
                Err(error) => {
                    println!("PEM ERROR {:?}", error);
                }
            }
        }
    }
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    Ok(file_info)
}
