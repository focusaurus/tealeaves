extern crate byteorder;
use base64;
use byteorder::{BigEndian, ReadBytesExt};
use file_info::{Algorithm,SshKey};
use nom_pem;
use nom_pem::headers::{HeaderEntry, ProcTypeType};
use nom::IResult;
use std::error::Error;
use std::io;
use std::io::{ErrorKind, Read};
use yasna;

fn bail(message: String) -> io::Error {
    return io::Error::new(ErrorKind::Other, message);
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

fn is_encrypted(headers: &Vec<HeaderEntry>) -> bool {
    headers
        .iter()
        .any(|header| match header {
                 &HeaderEntry::ProcType(_code, ref kind) => kind == &ProcTypeType::ENCRYPTED,
                 _ => false,
             })
}

fn bit_count(field: Vec<u8>) -> usize {
    // exclude leading null byte then convert bytes to bits
    (field.len() - 1) * 8
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

fn identify_openssh_v1(bytes: &[u8]) -> io::Result<SshKey> {
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
    let mut ssh_key = SshKey::new();
    // Make a reader for everything after the prefix plus the null byte
    let mut reader = io::BufReader::new(&bytes[prefix.len() + 1..]);
    let cipher_name = read_field(&mut reader)?;
    let _kdfname = read_field(&mut reader);
    // kdfoptions (don't really care)
    let _kdfoptions = read_field(&mut reader);
    let _pub_key_count = reader.read_u32::<BigEndian>()?;
    let _key_length = reader.read_u32::<BigEndian>()?;
    let key_type = read_field(&mut reader)?;
    ssh_key.is_encrypted = cipher_name.as_slice() != b"none";
    match key_type.as_slice() {
        b"ssh-ed25519" => {
            ssh_key.algorithm = Algorithm::Ed25519;
        }
        b"ssh-rsa" => {
            ssh_key.algorithm = Algorithm::Rsa;
            if !ssh_key.is_encrypted {
                let _rsa_version = read_field(&mut reader)?;
                let modulus = read_field(&mut reader)?;
                ssh_key.key_length = Some(bit_count(modulus));
            }
        }
        b"ssh-dss" => {
            ssh_key.algorithm = Algorithm::Dsa;
            if !ssh_key.is_encrypted {
                let int2 = read_field(&mut reader)?;
                ssh_key.key_length = Some(bit_count(int2));
            }
        }
        b"ecdsa-sha2-nistp256" => {
            ssh_key.algorithm = Algorithm::Ecdsa;
            ssh_key.key_length = Some(256);
        }
        b"ecdsa-sha2-nistp384" => {
            ssh_key.algorithm = Algorithm::Ecdsa;
            ssh_key.key_length = Some(384);
        }
        b"ecdsa-sha2-nistp521" => {
            ssh_key.algorithm = Algorithm::Ecdsa;
            ssh_key.key_length = Some(521);
        }
        _ => {
            ssh_key.algorithm = Algorithm::Unknown;
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
            // We don't need anything else but yasna panics if we leave unparsed data at the
            // end of the file so just read them all in. For the record they are
            // _pub_exp, _priv_exp, _prime1, _prime2, _exp1, _exp2, _coefficient
            for _ in 0..7 {
                let _int = reader.next().read_bigint()?;
            }
            return Ok(modulus.bits());
        })
    });
    match asn_result {
        Ok(bits) => Ok(bits),
        Err(error) => {
            // println!("ERROR {:?}", error);
            Err(error.description().to_string())
        }
    }
}

fn get_dsa_length(asn1_bytes: &[u8]) -> Result<usize, String> {
    let asn_result = yasna::parse_der(&asn1_bytes, |reader| {
        reader.read_sequence(|reader| {
            let _int1 = reader.next().read_i8()?;
            let int2 = reader.next().read_bigint()?;
            // We don't need anything else but yasna panics if we leave unparsed data at the
            // end of the file so just read them all in
            for _ in 0..4 {
                let _int = reader.next().read_bigint()?;
            }
            return Ok(int2.bits());
        })
    });
    match asn_result {
        Ok(bits) => Ok(bits),
        Err(error) => {
            // println!("ERROR {:?}", error);
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

pub fn private_key(bytes: &[u8]) -> Result<SshKey, String> {
    match nom_pem::decode_block(&bytes) {
        Ok(block) => {
            let mut ssh_key = SshKey::new();
            ssh_key.is_encrypted = is_encrypted(&block.headers);
            ssh_key.algorithm = match block.block_type {
                "DSA PRIVATE KEY" => Algorithm::Dsa,
                "EC PRIVATE KEY" => Algorithm::Ecdsa,
                "RSA PRIVATE KEY" => Algorithm::Rsa,
                _ => Algorithm::Unknown,
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
                    if has_prefix(b"openssh-key-v1", &block.data) {
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

fn algo_and_length(ssh_key: &mut SshKey, bytes: &[u8]) {
    let mut reader = io::BufReader::new(bytes);
    let algorithm = read_field(&mut reader).unwrap_or(vec![]);
    match algorithm.as_slice() {
        b"ecdsa-sha2-nistp256" => {
            ssh_key.algorithm = Algorithm::Ecdsa;
            ssh_key.key_length = Some(256);
        }
        b"ecdsa-sha2-nistp384" => {
            ssh_key.algorithm = Algorithm::Ecdsa;
            ssh_key.key_length = Some(384);
        }
        b"ecdsa-sha2-nistp521" => {
            ssh_key.algorithm = Algorithm::Ecdsa;
            ssh_key.key_length = Some(521);
        }
        b"ssh-ed25519" => {
            ssh_key.algorithm = Algorithm::Ed25519;
        }
        b"ssh-dss" => {
            ssh_key.algorithm = Algorithm::Dsa;
            let int1 = read_field(&mut reader).unwrap_or(vec![]);
            ssh_key.key_length = Some(bit_count(int1));
        }
        b"ssh-rsa" => {
            ssh_key.algorithm = Algorithm::Rsa;
            let _exponent = read_field(&mut reader).unwrap_or(vec![]);
            let modulus = read_field(&mut reader).unwrap_or(vec![]);
            ssh_key.key_length = Some(bit_count(modulus));
        }
        _ => (),
    }
}

pub fn public_key<'a>(bytes: &'a [u8]) -> io::Result<SshKey> {
    named!(space_sep, is_a_s!(" \t"));
    named!(value, is_not_s!(" \t"));
    named!(public_key<(&[u8], &[u8], &[u8])>,
      do_parse!(
        algorithm: value >>
        separator: space_sep >>
        payload: value >>
        separator: space_sep >>
        comment: is_not_s!("\r\n") >>
        (algorithm, payload, comment)
      )
    );
    match public_key(bytes) {
        IResult::Done(_input, (_label, payload, comment)) => {
            let mut ssh_key = SshKey::new();
            ssh_key.is_public = true;
            ssh_key.comment = Some(String::from_utf8_lossy(&comment).into_owned());
            let result = base64::decode(payload);
            if let Ok(decoded) = result {
                algo_and_length(&mut ssh_key, &decoded);
            }
            Ok(ssh_key)
        }
        IResult::Error(error) => Err(io::Error::new(io::ErrorKind::Other, error)),
        IResult::Incomplete(_needed) => {
            Err(io::Error::new(io::ErrorKind::Other, "Didn't fully parse"))
        }
    }
}
