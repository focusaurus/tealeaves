extern crate byteorder;
use base64;
use byteorder::{BigEndian, ReadBytesExt};
use file_info::{Algorithm, CertificateRequest, SshKey};
use nom_pem;
use nom_pem::{HeaderEntry, ProcTypeType};
use nom::IResult;
use std::io;
use std::io::Read;
// use std::io::{ErrorKind, Read};
use der_parser::{der_read_element_content_as, parse_der, parse_der_implicit, parse_der_integer,
                 parse_der_octetstring, DerObject, DerObjectContent, DerTag};
use der_parser::oid::Oid;

// My code does not directly use these names. Why do I need to `use` them?
use der_parser::der_read_element_header;

// My code does not directly use these names. Why do I need to `use` them?
use nom::{Err, ErrorKind, be_u32};

fn bail(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, message)
}

fn is_encrypted(headers: &[HeaderEntry]) -> bool {
    headers.iter().any(|header| match *header {
        HeaderEntry::ProcType(_code, ref kind) => kind == &ProcTypeType::ENCRYPTED,
        _ => false,
    })
}

fn bit_count(field: Vec<u8>) -> usize {
    field.len() * 8
}

// https://superuser.com/a/820638/34245
fn dsa_private(input: &[u8]) -> Result<Algorithm, String> {
    match parse_der_sequence_defined!(
        input,
        parse_der_integer, // version
        parse_der_integer, // p
        parse_der_integer, // q
        parse_der_integer, // g
        parse_der_integer, // public_key
        parse_der_integer, // private_key
    ) {
        IResult::Done(_unparsed_suffix, der) => {
            assert_eq!(_unparsed_suffix.len(), 0);
            let der_objects = der.as_sequence().unwrap();
            let p_integer = der_objects[1].content.as_slice().unwrap();
            // strip leading null byte
            let p_integer = &p_integer[1..];
            return Ok(Algorithm::Dsa(p_integer.to_owned()));
        }
        IResult::Error(error) => Err(format!("{}", error)),
        IResult::Incomplete(needed) => Err(format!("Incomplete parse: {:?}", needed)),
    }
}

// https://tools.ietf.org/html/rfc3447#appendix-A.1.2
/*
 An RSA private key should be represented with the ASN.1 type
   RSAPrivateKey:

      RSAPrivateKey ::= SEQUENCE {
          version           Version,
          modulus           INTEGER,  -- n
          publicExponent    INTEGER,  -- e
          privateExponent   INTEGER,  -- d
          prime1            INTEGER,  -- p
          prime2            INTEGER,  -- q
          exponent1         INTEGER,  -- d mod (p-1)
          exponent2         INTEGER,  -- d mod (q-1)
          coefficient       INTEGER,  -- (inverse of q) mod p
          otherPrimeInfos   OtherPrimeInfos OPTIONAL
      }
*/
fn rsa_private(input: &[u8]) -> Result<Algorithm, String> {
    match parse_der_sequence_defined!(
        input,
        parse_der_integer,
        parse_der_integer,
        parse_der_integer,
        parse_der_integer,
        parse_der_integer,
        parse_der_integer,
        parse_der_integer,
        parse_der_integer,
        parse_der_integer,
    ) {
        IResult::Done(_unparsed_suffix, der) => {
            assert_eq!(_unparsed_suffix.len(), 0);
            let der_objects = der.as_sequence().unwrap();
            // modulus (n) is at index 1
            // I believe this indexing and unwrapping is safe because
            // if it parsed correctly, the data should be there
            let modulus = der_objects[1].content.as_slice().unwrap();
            // Skip leading null byte.
            // Also we copy the modulus to an owned Vec<u8> here because
            // we want to allow the secret parts of the private key to be freed.
            // We want the secrets in memory as briefly as possible.
            let modulus = modulus[1..].to_owned();
            Ok(Algorithm::Rsa(modulus))
        }
        IResult::Error(error) => {
            // eprintln!("{}", error);
            Err(format!("{}", error))
        }
        IResult::Incomplete(needed) => Err(format!("Incomplete parse: {:?}", needed)),
    }
}

fn der_read_oid_content(i: &[u8], _tag: u8, len: usize) -> IResult<&[u8], DerObjectContent, u32> {
    der_read_element_content_as(i, DerTag::Oid as u8, len)
}

fn der_read_bitstring_content(
    i: &[u8],
    _tag: u8,
    len: usize,
) -> IResult<&[u8], DerObjectContent, u32> {
    der_read_element_content_as(i, DerTag::BitString as u8, len)
}

fn parse_oid(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_der_implicit(i, 0, der_read_oid_content)
}

fn parse_bitstring(i: &[u8]) -> IResult<&[u8], DerObject> {
    parse_der_implicit(i, 1, der_read_bitstring_content)
}

// http://www.secg.org/sec1-v2.pdf
/*
SEC1-PDU ::= CHOICE {
privateKey [0] ECPrivateKey,
spki [1] SubjectPublicKeyInfo, ecdsa [2] ECDSA-Signature,
ecies [3] ECIES-Ciphertext-Value, sharedinfo [4] ASN1SharedInfo, ...
}
    0:d=0  hl=2 l= 119 cons: SEQUENCE
    2:d=1  hl=2 l=   1 prim: INTEGER           :01
    5:d=1  hl=2 l=  32 prim: OCTET STRING
         [HEX DUMP]:
         0C52C1C9D109E29905AD274AEC946E18DF72C37BA8090D96A60A4229073B9F40
   39:d=1  hl=2 l=  10 cons: cont [ 0 ]
   41:d=2  hl=2 l=   8 prim: OBJECT            :prime256v1
   51:d=1  hl=2 l=  68 cons: cont [ 1 ]
   53:d=2  hl=2 l=  66 prim: BIT STRING
*/
fn ecdsa_private(input: &[u8]) -> Result<Algorithm, String> {
    match parse_der_sequence_defined!(
        input,
        parse_der_integer,
        parse_der_octetstring,
        parse_oid,
        parse_bitstring,
    ) {
        IResult::Done(_unparsed_suffix, der) => {
            assert_eq!(_unparsed_suffix.len(), 0);
            let content = der.as_sequence().unwrap()[2]
                .content
                .as_context_specific()
                .unwrap()
                .1
                .unwrap()
                .content;
            let oid = content.as_oid().unwrap();
            if oid == &Oid::from(&[0u64, 6, 8, 42, 840, 10_045, 3, 1, 7]) {
                return Ok(Algorithm::Ecdsa(256));
            }
            if oid == &Oid::from(&[0u64, 6, 5, 43, 132, 0, 34]) {
                return Ok(Algorithm::Ecdsa(384));
            }
            if oid == &Oid::from(&[0u64, 6, 5, 43, 132, 0, 35]) {
                return Ok(Algorithm::Ecdsa(521));
            }
            return Ok(Algorithm::Unknown);
        }
        IResult::Error(error) => Err(format!("{}", error)),
        IResult::Incomplete(needed) => Err(format!("Incomplete parse: {:?}", needed)),
    }
}

/*
byte[]	AUTH_MAGIC
string	ciphername
string	kdfname
string	kdfoptions
int	number of keys N
string	publickey1
string	publickey2
*/
named!(
    nom_openssh_key_v1<(&[u8], &[u8])>,
    do_parse!(
        tag!(b"openssh-key-v1\0") >> cipher_name: length_bytes!(be_u32)
            >> kdf_name: length_bytes!(be_u32) >> kdf_options: length_bytes!(be_u32)
            >> key_count: tag!(&[0, 0, 0, 1]) >> key: length_bytes!(be_u32)
            >> (cipher_name, key)
    )
);

named!(
    nom_ssh_rsa<(&[u8], &[u8])>,
    do_parse!(
        cipher_name: length_bytes!(be_u32) >> _version: length_bytes!(be_u32)
            >> modulus: length_bytes!(be_u32) >> (cipher_name, &modulus[1..])
    )
);

named!(
    nom_ssh_dss<(&[u8], &[u8])>,
    do_parse!(
        cipher_name: length_bytes!(be_u32) >> p_integer: length_bytes!(be_u32)
        >> (cipher_name, &p_integer[1..])
    )
);

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

fn openssh_key_v1_private(bytes: &[u8]) -> Result<SshKey, String> {
    match nom_openssh_key_v1(bytes) {
        IResult::Done(_tail, (cipher_name, key_bytes)) => {
            let mut ssh_key: SshKey = Default::default();
            ssh_key.is_encrypted = cipher_name != b"none";
            // Skip 4-byte length indicator
            let algorithm_name = &key_bytes[4..];
            if algorithm_name.starts_with(b"ssh-dss") {
                ssh_key.algorithm = Algorithm::Dsa(vec![]);
                if !ssh_key.is_encrypted {
                    return match nom_ssh_dss(&key_bytes) {
                        IResult::Done(_tail, (algorithm, p_integer)) => {
                            ssh_key.algorithm = Algorithm::Dsa(p_integer.to_owned());
                            Ok(ssh_key)
                        }
                        IResult::Error(_error) => Err("Parse error".into()),
                        IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
                    };
                }
            }
            if algorithm_name.starts_with(b"ssh-rsa") {
                ssh_key.algorithm = Algorithm::Rsa(vec![]);
                if !ssh_key.is_encrypted {
                    return match nom_ssh_rsa(&key_bytes) {
                        IResult::Done(_tail, (algorithm, p_integer)) => {
                            ssh_key.algorithm = Algorithm::Dsa(p_integer.to_owned());
                            Ok(ssh_key)
                        }
                        IResult::Error(_error) => Err("Parse error".into()),
                        IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
                    };
                }
            }
            if algorithm_name.starts_with(b"ssh-dss") {
                ssh_key.algorithm = Algorithm::Dsa(vec![]);
                // if !ssh_key.is_encrypted {
                //     let p_integer = read_field(&mut reader)?;
                //     ssh_key.algorithm = Algorithm::Dsa(p_integer[1..].to_owned());
                // }
            }
            if algorithm_name.starts_with(b"ecdsa-sha2-nistp256") {
                ssh_key.algorithm = Algorithm::Ecdsa(256);
            }
            if algorithm_name.starts_with(b"ecdsa-sha2-nistp384") {
                ssh_key.algorithm = Algorithm::Ecdsa(384);
            }
            if algorithm_name.starts_with(b"ecdsa-sha2-nistp521") {
                ssh_key.algorithm = Algorithm::Ecdsa(521);
            }
            Ok(ssh_key)
        }
        IResult::Error(_error) => Err("Parse error".into()),
        IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
    }
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
            ssh_key.algorithm = Algorithm::Rsa(vec![]);
            if !ssh_key.is_encrypted {
                // fixme figure out if this is ASN.1 or not
                let _rsa_version = read_field(&mut reader)?;
                let modulus = read_field(&mut reader)?;
                // skip null byte
                ssh_key.algorithm = Algorithm::Rsa(modulus[1..].to_owned());
            }
        }
        b"ssh-dss" => {
            ssh_key.algorithm = Algorithm::Dsa(vec![]);
            if !ssh_key.is_encrypted {
                let p_integer = read_field(&mut reader)?;
                ssh_key.algorithm = Algorithm::Dsa(p_integer[1..].to_owned());
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

fn length_seq1(asn1_bytes: &[u8]) -> Result<usize, String> {
    let der_result = parse_der(&asn1_bytes);
    match der_result {
        IResult::Done(_input, der) => {
            let seq = der.as_sequence().unwrap();
            let _version = seq[0].as_u32().unwrap();
            let field = seq[1].content.as_slice().unwrap();
            // Length in bits, discount null byte at start then multiply byte count by 8
            Ok((field.len() - 1) * 8)
        }
        IResult::Error(error) => Err(format!("Error parsing key file: {}", error)),
        IResult::Incomplete(_needed) => Err("Error parsing: incomplete".into()),
    }
}

pub fn private_key(bytes: &[u8]) -> Result<SshKey, String> {
    match nom_pem::decode_block(bytes) {
        Ok(block) => {
            let mut ssh_key: SshKey = Default::default();
            ssh_key.is_encrypted = is_encrypted(&block.headers);
            ssh_key.algorithm = match block.block_type {
                "DSA PRIVATE KEY" => Algorithm::Dsa(vec![]),
                "EC PRIVATE KEY" => Algorithm::Ecdsa(0),
                "RSA PRIVATE KEY" => Algorithm::Rsa(vec![]),
                _ => Algorithm::Unknown,
            };
            if ssh_key.is_encrypted {
                // Can't determine details without passphrase
                return Ok(ssh_key);
            }
            match block.block_type {
                "CERTIFICATE REQUEST" => {
                    // TODO handle CSR
                    ssh_key.algorithm = Algorithm::Dsa(vec![]);
                }
                "DSA PRIVATE KEY" => {
                    ssh_key.algorithm = dsa_private(&block.data)?;
                }
                "RSA PRIVATE KEY" => {
                    ssh_key.algorithm = rsa_private(&block.data)?;
                }
                "EC PRIVATE KEY" => {
                    ssh_key.algorithm = ecdsa_private(&block.data)?;
                }
                "OPENSSH PRIVATE KEY" => {
                    if block.data.starts_with(b"openssh-key-v1\0") {
                        // match identify_openssh_v1(&block.data) {
                        //     Ok(key) => {
                        //         ssh_key = key;
                        //     }
                        //     Err(error) => {
                        //         return Err(format!("openssh-key-v1 error: {:?}", error));
                        //     }
                        // }
                        match openssh_key_v1_private(&block.data) {
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
            let p_integer = read_field(&mut reader).unwrap_or(vec![]);
            ssh_key.algorithm = Algorithm::Dsa(p_integer[1..].to_owned());
        }
        b"ssh-rsa" => {
            let _exponent = read_field(&mut reader).unwrap_or(vec![]);
            let modulus = read_field(&mut reader).unwrap_or(vec![]);
            ssh_key.algorithm = Algorithm::Rsa(modulus[1..].to_owned());
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
        IResult::Error(_error) => Err("Parse error".into()),
        IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
    }
}

fn parse_certificate_request(asn1_bytes: &[u8]) {
    let der_result = parse_der(&asn1_bytes);
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
