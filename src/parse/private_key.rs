use byteorder::{BigEndian, ReadBytesExt};
use file_info;
use nom_pem;
use nom_pem::headers::{HeaderEntry, ProcTypeType};
use parse;
use std::error::Error;
use std::io;
use yasna;

fn is_encrypted(headers: &Vec<HeaderEntry>) -> bool {
    headers
        .iter()
        .any(|header| match header {
                 &HeaderEntry::ProcType(_code, ref kind) => kind == &ProcTypeType::ENCRYPTED,
                 _ => false,
             })
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
    let cipher_name = parse::read_field(&mut reader)?;
    let _kdfname = parse::read_field(&mut reader);
    // kdfoptions (don't really care)
    let _kdfoptions = parse::read_field(&mut reader);
    let _pub_key_count = reader.read_u32::<BigEndian>()?;
    let _key_length = reader.read_u32::<BigEndian>()?;
    let key_type = parse::read_field(&mut reader)?;
    ssh_key.is_encrypted = match cipher_name.as_slice() {
        b"none" => false,
        _ => true,
    };
    println!("key type {:?}", String::from_utf8_lossy(&key_type));
    match key_type.as_slice() {
        b"ssh-ed25519" => {
            ssh_key.algorithm = Some("ed25519".to_string());
        }
        b"ssh-rsa" => {
            ssh_key.algorithm = Some("rsa".to_string());
            let _rsa_version = parse::read_field(&mut reader)?;
            let modulus = parse::read_field(&mut reader)?;
            // Discard null byte then convert bytes to bits
            ssh_key.key_length = Some((modulus.len() - 1) * 8);
        }
        b"ssh-dss" => {
            ssh_key.algorithm = Some("dsa".to_string());
            let int2 = parse::read_field(&mut reader)?;
            ssh_key.key_length = Some((int2.len() - 1) * 8);
        }
        b"ecdsa-sha2-nistp256" => {
            ssh_key.algorithm = Some("ecdsa".to_string());
            ssh_key.key_length = Some(256);
        }
        b"ecdsa-sha2-nistp384" => {
            ssh_key.algorithm = Some("ecdsa".to_string());
            ssh_key.key_length = Some(384);
        }
        b"ecdsa-sha2-nistp521" => {
            ssh_key.algorithm = Some("ecdsa".to_string());
            ssh_key.key_length = Some(521);
        }
        _ => {
            ssh_key.algorithm = None;
        }
    };
    if ssh_key.is_encrypted {
        return Ok(ssh_key);
    }

    Ok(ssh_key)
}

fn get_rsa_length(asn1_bytes: &[u8]) -> Result<usize, String> {
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
        Ok(bits) => Ok(bits),
        Err(error) => {
            println!("ERROR {:?}", error);
            Err(error.description().to_string())
        }
    }
}

fn get_dsa_length(asn1_bytes: &[u8]) -> Result<usize, String> {
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
    match asn_result {
        Ok(bits) => Ok(bits),
        Err(error) => {
            println!("ERROR {:?}", error);
            Err(error.description().to_string())
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

fn dsa(block: &nom_pem::Block) -> Result<file_info::SshKey, String> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = false;
    ssh_key.algorithm = Some("dsa".to_string());
    ssh_key.is_encrypted = is_encrypted(&block.headers);
    if ssh_key.is_encrypted {
        return Ok(ssh_key);
    }
    return match get_dsa_length(&block.data) {
               Ok(length) => {
        ssh_key.key_length = Some(length);
        Ok(ssh_key)
    }
               Err(message) => Err(message),
           };
}

pub fn pem(bytes: &[u8]) -> Result<file_info::SshKey, String> {
    match nom_pem::decode_block(&bytes) {
        Ok(block) => {
            let mut ssh_key = file_info::SshKey::new();
            ssh_key.is_encrypted = is_encrypted(&block.headers);
            ssh_key.algorithm = match block.block_type {
                "DSA PRIVATE KEY" => Some("dsa".to_string()),
                "RSA PRIVATE KEY" => Some("rsa".to_string()),
                "EC PRIVATE KEY" => Some("ecdsa".to_string()),
                _ => None,
            };
            if ssh_key.is_encrypted {
                // Can't determine details without passphrase
                return Ok(ssh_key);
            }
            match block.block_type {
                "DSA PRIVATE KEY" => {
                    ssh_key.key_length = Some(get_dsa_length(&block.data)?);
                }
                "RSA PRIVATE KEY" => {
                    ssh_key.key_length = Some(get_rsa_length(&block.data)?);
                }
                "EC PRIVATE KEY" => {
                    ssh_key.key_length = Some(get_ecdsa_length(&block.data)?);
                }
                "OPENSSH PRIVATE KEY" => {
                    if parse::has_prefix(b"openssh-key-v1", &block.data) {
                        match identify_openssh_v1(&block.data) {
                            Ok(key) => {
                                ssh_key = key;
                            }
                            Err(error) => {
                                return Err(format!("openssh-key-v1 error: {:?}", error));
                            }
                        }
                    }
                }
                "ENCRYPTED PRIVATE KEY" => {
                    ssh_key.is_encrypted = true;
                }
                _ => (),
            };
            Ok(ssh_key)
        }
        Err(error) => {
            return Err(format!("PEM error: {:?}", error));
        }
    }
}
