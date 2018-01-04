extern crate byteorder;
extern crate der_parser;
use base64;
use byteorder::{BigEndian, ReadBytesExt};
use file_info::{Algorithm, CertificateRequest, SshKey};
use nom_pem;
use nom_pem::{HeaderEntry, ProcTypeType};
use nom::IResult;
use std::error::Error;
use std::io;
use std::io::{ErrorKind, Read};
use yasna;

fn bail(message: String) -> io::Error {
    io::Error::new(ErrorKind::Other, message)
}

fn is_encrypted(headers: &[HeaderEntry]) -> bool {
    headers.iter().any(|header| match *header {
        HeaderEntry::ProcType(_code, ref kind) => kind == &ProcTypeType::ENCRYPTED,
        _ => false,
    })
}

fn bit_count(field: &[u8]) -> usize {
    // exclude leading null byte then convert bytes to bits
    (field.len() - 1) * 8
}

/// Read a length-prefixed field in the format openssh uses
/// which is a 4-byte big-endian u32 length
/// followed by that many bytes of payload
fn read_field<R: ReadBytesExt + Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = reader.read_u32::<BigEndian>()?;
    if len > 4096 {
        return Err(bail("Field size too large. File possibly corrupt.".into()));
    }
    let mut word = vec![0u8; len as usize];
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
    let mut ssh_key: SshKey = Default::default();
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
            ssh_key.algorithm = Algorithm::Rsa(0);
            if !ssh_key.is_encrypted {
                let _rsa_version = read_field(&mut reader)?;
                let modulus = read_field(&mut reader)?;
                ssh_key.algorithm = Algorithm::Rsa(bit_count(&modulus));
            }
        }
        b"ssh-dss" => {
            ssh_key.algorithm = Algorithm::Dsa(1024);
            if !ssh_key.is_encrypted {
                let int2 = read_field(&mut reader)?;
                ssh_key.algorithm = Algorithm::Dsa(bit_count(&int2));
            }
        }
        b"ecdsa-sha2-nistp256" => {
            ssh_key.algorithm = Algorithm::Ecdsa(256);
        }
        b"ecdsa-sha2-nistp384" => {
            ssh_key.algorithm = Algorithm::Ecdsa(384);
        }
        b"ecdsa-sha2-nistp521" => {
            ssh_key.algorithm = Algorithm::Ecdsa(521);
        }
        _ => {
            ssh_key.algorithm = Algorithm::Unknown;
        }
    };
    Ok(ssh_key)
}

fn get_rsa_length(asn1_bytes: &[u8]) -> Result<usize, String> {
    let der_result = der_parser::parse_der(&asn1_bytes);
    match der_result {
        IResult::Done(_input, der) => {
            let seq = der.as_sequence().unwrap();
            let _rsa_version = seq[0].as_u32().unwrap();
            let modulus = seq[1].content.as_slice().unwrap();
            // Length in bits, discount null byte at start then multiply byte count by 8
            Ok((modulus.len() - 1) * 8)
        }
        IResult::Error(error) => {
            eprintln!("{}", error);
            Err("Error parsing RSA".to_string())
        }
        IResult::Incomplete(_needed) => {
            eprintln!("{:?}", _needed);
            Err("Error incomplete RSA".to_string())
            // Err(der_parser::DerError::DerValueError)
        }
    }
}

fn get_dsa_length(asn1_bytes: &[u8]) -> Result<usize, String> {
    let asn_result = yasna::parse_der(asn1_bytes, |reader| {
        reader.read_sequence(|reader| {
            let _int1 = reader.next().read_i8()?;
            let int2 = reader.next().read_bigint()?;
            // We don't need anything else but yasna panics if we leave unparsed data at the
            // end of the file so just read them all in
            for _ in 0..4 {
                let _int = reader.next().read_bigint()?;
            }
            Ok(int2.bits())
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
    let asn_result = yasna::parse_der(asn1_bytes, |reader| {
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

            if oid.components().as_slice() == [1u64, 2, 840, 10_045, 3, 1, 7] {
                return Ok(256);
            }
            if oid.components().as_slice() == [1u64, 3, 132, 0, 34] {
                return Ok(384);
            }
            if oid.components().as_slice() == [1u64, 3, 132, 0, 35] {
                return Ok(521);
            }

            Ok(0)
        })
    });
    match asn_result {
        Ok(0) => Err("Unrecognized ecdsa curve".into()),
        Ok(bits) => Ok(bits),
        Err(error) => Err(error.description().to_string()),
    }
}

pub fn private_key(bytes: &[u8]) -> Result<SshKey, String> {
    match nom_pem::decode_block(bytes) {
        Ok(block) => {
            let mut ssh_key: SshKey = Default::default();
            ssh_key.is_encrypted = is_encrypted(&block.headers);
            ssh_key.algorithm = match block.block_type {
                "DSA PRIVATE KEY" => Algorithm::Dsa(1024),
                "EC PRIVATE KEY" => Algorithm::Ecdsa(0),
                "RSA PRIVATE KEY" => Algorithm::Rsa(0),
                _ => Algorithm::Unknown,
            };
            if ssh_key.is_encrypted {
                // Can't determine details without passphrase
                return Ok(ssh_key);
            }
            match block.block_type {
                "CERTIFICATE REQUEST" => {
                    ssh_key.algorithm = Algorithm::Dsa(get_dsa_length(&block.data)?);
                }
                "DSA PRIVATE KEY" => {
                    ssh_key.algorithm = Algorithm::Dsa(get_dsa_length(&block.data)?);
                }
                "RSA PRIVATE KEY" => {
                    ssh_key.algorithm = Algorithm::Rsa(get_rsa_length(&block.data)?);
                }
                "EC PRIVATE KEY" => {
                    ssh_key.algorithm = Algorithm::Ecdsa(get_ecdsa_length(&block.data)?);
                }
                "OPENSSH PRIVATE KEY" => {
                    if block.data.starts_with(b"openssh-key-v1") {
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
        Err(error) => Err(format!("PEM error: {:?}", error)),
    }
}

fn algo_and_length(ssh_key: &mut SshKey, bytes: &[u8]) {
    let mut reader = io::BufReader::new(bytes);
    let algorithm = read_field(&mut reader).unwrap_or(vec![]);
    match algorithm.as_slice() {
        b"ecdsa-sha2-nistp256" => {
            ssh_key.algorithm = Algorithm::Ecdsa(256);
        }
        b"ecdsa-sha2-nistp384" => {
            ssh_key.algorithm = Algorithm::Ecdsa(384);
        }
        b"ecdsa-sha2-nistp521" => {
            ssh_key.algorithm = Algorithm::Ecdsa(521);
        }
        b"ssh-ed25519" => {
            ssh_key.algorithm = Algorithm::Ed25519;
        }
        b"ssh-dss" => {
            let int1 = read_field(&mut reader).unwrap_or(vec![]);
            ssh_key.algorithm = Algorithm::Dsa(bit_count(&int1));
        }
        b"ssh-rsa" => {
            let _exponent = read_field(&mut reader).unwrap_or(vec![]);
            let modulus = read_field(&mut reader).unwrap_or(vec![]);
            ssh_key.algorithm = Algorithm::Rsa(bit_count(&modulus));
        }
        _ => (),
    }
}

pub fn public_key(bytes: &[u8]) -> Result<SshKey, String> {
    named!(space_sep, is_a_s!(" \t"));
    named!(value, is_not_s!(" \t"));
    named!(
        nom_public_key<(&[u8], &[u8], &[u8])>,
        do_parse!(
            algorithm: value >> separator: space_sep >> payload: value >> separator: space_sep
                >> comment: is_not_s!("\r\n") >> (algorithm, payload, comment)
        )
    );
    match nom_public_key(bytes) {
        IResult::Done(_input, (_label, payload, comment)) => {
            let mut ssh_key: SshKey = Default::default();
            ssh_key.is_public = true;
            ssh_key.comment = Some(String::from_utf8_lossy(comment).into_owned());
            let result = base64::decode(payload);
            if let Ok(decoded) = result {
                algo_and_length(&mut ssh_key, &decoded);
            }
            Ok(ssh_key)
        }
        IResult::Error(error) => Err("Parse error".into()),
        IResult::Incomplete(_needed) => Err("Didn't fully parse".to_string()),
    }
}

fn parse_certificate_request(asn1_bytes: &[u8]) {
    let der_result = der_parser::parse_der(&asn1_bytes);
    match der_result {
        IResult::Done(_input, der) => {
            assert_eq!(_input.len(), 0);
            let seq0 = der.as_sequence().unwrap();
            let seq1 = seq0[0].as_sequence().unwrap();
            let version = &seq1[0].content.as_u32().unwrap();
            println!("version {:?}", version);
            let seq2 = &seq1[1].content.as_sequence().unwrap();

            for i in 0..6 {
                let seq4 = &seq2[i].as_set().unwrap()[0].as_sequence().unwrap();
                let oid = &seq4[0].as_oid().unwrap();
                println!("oid {:?}", oid);
                let value = &seq4[1].as_slice().unwrap();
                println!("value {}", String::from_utf8_lossy(value));
            }
            // let seq4 = &seq2[1].as_set().unwrap()[0].as_sequence().unwrap();
            // let oid = &seq4[0].as_oid().unwrap();
            // println!("oid {:?}", oid);
            // let state = &seq4[1].as_slice().unwrap();
            // println!("state {}", String::from_utf8_lossy(state));
            // // let country = &seq3[1]
            // if seq1.len() < 1 {
            //     //return Err(der_parser::DerError::DerValueError);
            //     return;
            // }
        }
        IResult::Error(error) => {
            eprintln!("{}", error);
            // Err(der_parser::DerError::DerValueError)
            // Err(io::Error::new(io::ErrorKind::Other, error))
        }
        IResult::Incomplete(_needed) => {
            eprintln!("{:?}", _needed);
            // Err(der_parser::DerError::DerValueError)
        }
    };
    /*    let asn_result = yasna::parse_der(asn1_bytes, |reader| {
        reader.read_sequence(|reader| {
            let wtf = reader.next().read_i8()?;
            reader.read_sequence(|reader|{
                let object_type  = reader.next().read_oid().unwrap();
                let country = reader.next().read_blah().unwrap();

            })
            // let oid = reader
            //     .next()
            //     .read_tagged(yasna::Tag::context(0), |reader| reader.read_i8())
            //     .unwrap();
        })
    });
    match asn_result {
        Ok(bits) => Ok(bits),
        Err(error) => {
            // println!("ERROR {:?}", error);
            Err(error.description().to_string())
        }
    };
*/
}
pub fn certificate_request(bytes: &[u8]) -> Result<CertificateRequest, String> {
    match nom_pem::decode_block(bytes) {
        Ok(block) => {
            let mut certificate_request: CertificateRequest = Default::default();
            certificate_request.is_encrypted = is_encrypted(&block.headers);
            if certificate_request.is_encrypted {
                // Can't determine details without passphrase
                return Ok(certificate_request);
            }
            parse_certificate_request(&block.data);
            Ok(certificate_request)
        }
        Err(error) => Err(format!("PEM error: {:?}", error)),
    }
}
