use certificate::Certificate;
use ssh_key::{Algorithm, SshKey};
use base64;
use nom_pem;
use nom_pem::{HeaderEntry, ProcTypeType};
use nom::IResult;
use x509_parser;
use time;
use der_parser::{der_read_element_content_as, parse_der_implicit, parse_der_integer,
                 parse_der_octetstring, DerObject, DerObjectContent, DerTag};
use der_parser::oid::Oid;

// My code does not directly use these names. Why do I need to `use` them?
use der_parser::der_read_element_header;

// My code does not directly use these names. Why do I need to `use` them?
use nom::{Err, ErrorKind, be_u32};

fn is_encrypted(headers: &[HeaderEntry]) -> bool {
    headers.iter().any(|header| match *header {
        HeaderEntry::ProcType(_code, ref kind) => kind == &ProcTypeType::ENCRYPTED,
        _ => false,
    })
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
            let seq = der.as_sequence().unwrap();
            let oid = seq[2].content.as_context_specific().unwrap();
            let oid = oid.1.unwrap();
            let oid = oid.content.as_oid().unwrap();
            let point = seq[3].content.as_context_specific().unwrap();
            let point = point.1.unwrap().content.as_slice().unwrap();
            // strip off 2 bytes of the ASN wrapper
            let point = (&point[2..]).to_owned();
            if oid == &Oid::from(&[0u64, 6, 8, 42, 840, 10_045, 3, 1, 7]) {
                return Ok(Algorithm::Ecdsa("nistp256".into(), point));
            }
            if oid == &Oid::from(&[0u64, 6, 5, 43, 132, 0, 34]) {
                return Ok(Algorithm::Ecdsa("nistp384".into(), point));
            }
            if oid == &Oid::from(&[0u64, 6, 5, 43, 132, 0, 35]) {
                return Ok(Algorithm::Ecdsa("nistp521".into(), point));
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
    nom_openssh_key_v1_private<(&[u8], &[u8])>,
    do_parse!(
        tag!(b"openssh-key-v1\0") >> cipher_name: length_bytes!(be_u32)
            >> kdf_name: length_bytes!(be_u32) >> kdf_options: length_bytes!(be_u32)
            >> key_count: tag!(&[0, 0, 0, 1]) >> key: length_bytes!(be_u32)
            >> (cipher_name, key)
    )
);

named!(
    nom_ed25519<(&[u8])>,
    do_parse!(cipher_name: length_bytes!(be_u32) >> point: length_bytes!(be_u32) >> (&point))
);

named!(
    nom_rsa<(&[u8])>,
    do_parse!(
        cipher_name: length_bytes!(be_u32) >> _ver_or_exp: length_bytes!(be_u32)
            >> modulus: length_bytes!(be_u32) >> (&modulus[1..])
    )
);

named!(
    nom_dss<(&[u8])>,
    do_parse!(
        cipher_name: length_bytes!(be_u32) >> p_integer: length_bytes!(be_u32) >> (&p_integer[1..])
    )
);

named!(
    nom_ecdsa<(&[u8], &[u8])>,
    do_parse!(
        key_type: length_bytes!(be_u32) >> curve: length_bytes!(be_u32)
            >> point: length_bytes!(be_u32) >> (&curve, &point)
    )
);

fn openssh_key_v1_private(bytes: &[u8]) -> Result<SshKey, String> {
    match nom_openssh_key_v1_private(bytes) {
        IResult::Done(_tail, (cipher_name, key_bytes)) => {
            let mut ssh_key: SshKey = Default::default();
            ssh_key.is_encrypted = cipher_name != b"none";
            match peek_algorithm(ssh_key.is_encrypted, &key_bytes) {
                Ok(algorithm) => {
                    ssh_key.algorithm = algorithm;
                    Ok(ssh_key)
                }
                Err(message) => Err(message),
            }
        }
        IResult::Error(_error) => Err("Parse error".into()),
        IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
    }
}

pub fn private_key(bytes: &[u8]) -> Result<SshKey, String> {
    match nom_pem::decode_block(bytes) {
        Ok(block) => {
            let mut ssh_key: SshKey = Default::default();
            ssh_key.is_encrypted = is_encrypted(&block.headers);
            ssh_key.algorithm = match block.block_type {
                "DSA PRIVATE KEY" => Algorithm::Dsa(vec![]),
                "EC PRIVATE KEY" => Algorithm::Ecdsa("unkown".into(), vec![]),
                "RSA PRIVATE KEY" => Algorithm::Rsa(vec![]),
                _ => Algorithm::Unknown,
            };
            if ssh_key.is_encrypted {
                // Can't determine details without passphrase
                return Ok(ssh_key);
            }
            match block.block_type {
                // "CERTIFICATE REQUEST" => {
                //     // TODO handle CSR
                //     ssh_key.algorithm = Algorithm::Dsa(vec![]);
                // }
                // "CERTIFICATE" => {
                //     let mut certificate: TlsCertificate = Default::default();
                //     return Ok(certificate);
                // }
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

named!(space_sep, is_a_s!(" \t"));
named!(value, is_not_s!(" \t"));
named!(
    nom_public_key<(&[u8], &[u8], &[u8])>,
    do_parse!(
        algorithm: value >> separator: space_sep >> payload: value >> separator: space_sep
            >> comment: is_not_s!("\r\n") >> (algorithm, payload, comment)
    )
);

fn peek_algorithm(is_encrypted: bool, key_bytes: &[u8]) -> Result<Algorithm, String> {
    if key_bytes.len() < 4 {
        return Err("Too short to be a valid ssh key".into());
    }
    let mut algorithm = Algorithm::Unknown;
    // Skip 4-byte length indicator
    let algorithm_name = &key_bytes[4..];
    if algorithm_name.starts_with(b"ssh-ed25519") {
        algorithm = Algorithm::Ed25519(vec![]);
    }
    if algorithm_name.starts_with(b"ecdsa-sha2-nistp256") {
        algorithm = Algorithm::Ecdsa("nistp256".into(), vec![]);
    }
    if algorithm_name.starts_with(b"ecdsa-sha2-nistp384") {
        algorithm = Algorithm::Ecdsa("nistp384".into(), vec![]);
    }
    if algorithm_name.starts_with(b"ecdsa-sha2-nistp521") {
        algorithm = Algorithm::Ecdsa("nistp521".into(), vec![]);
    }
    if algorithm_name.starts_with(b"ssh-dss") {
        algorithm = Algorithm::Dsa(vec![]);
    }
    if algorithm_name.starts_with(b"ssh-rsa") {
        algorithm = Algorithm::Rsa(vec![]);
    }
    if is_encrypted {
        return Ok(algorithm);
    }
    if algorithm_name.starts_with(b"ssh-ed25519") {
        return match nom_ed25519(&key_bytes) {
            IResult::Done(_tail, point) => Ok(Algorithm::Ed25519(point.to_owned())),
            IResult::Error(_error) => Err("Parse error".into()),
            IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
        };
    }
    if algorithm_name.starts_with(b"ssh-rsa") {
        return match nom_rsa(&key_bytes) {
            IResult::Done(_tail, modulus) => Ok(Algorithm::Rsa(modulus.to_owned())),
            IResult::Error(_error) => Err("Parse error".into()),
            IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
        };
    }
    if algorithm_name.starts_with(b"ssh-dss") {
        return match nom_dss(&key_bytes) {
            IResult::Done(_tail, p_integer) => Ok(Algorithm::Dsa(p_integer.to_owned())),
            IResult::Error(_error) => Err("Parse error".into()),
            IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
        };
    }
    if algorithm_name.starts_with(b"ecdsa-sha2-nistp") {
        return match nom_ecdsa(&key_bytes) {
            IResult::Done(_tail, (curve, point)) => Ok(Algorithm::Ecdsa(
                String::from_utf8_lossy(curve).into(),
                point.to_owned(),
            )),
            IResult::Error(_error) => Err("Parse error".into()),
            IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
        };
    }
    Ok(algorithm)
}

pub fn public_key(bytes: &[u8]) -> Result<SshKey, String> {
    match nom_public_key(bytes) {
        IResult::Done(_input, (_label, payload, comment)) => {
            let mut ssh_key: SshKey = Default::default();
            ssh_key.is_public = true;
            ssh_key.comment = Some(String::from_utf8_lossy(comment).into_owned());
            match base64::decode(payload) {
                Ok(key_bytes) => match peek_algorithm(false, &key_bytes) {
                    Ok(algorithm) => {
                        ssh_key.algorithm = algorithm;
                        Ok(ssh_key)
                    }
                    Err(message) => Err(message),
                },
                Err(_) => Err("Invalid Base64".into()),
            }
        }
        IResult::Error(_error) => Err("Parse error".into()),
        IResult::Incomplete(_needed) => Err("Didn't fully parse".into()),
    }
}
/*
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
*/
//
// pub fn certificate_request(bytes: &[u8]) -> Result<CertificateRequest, String> {
//     match nom_pem::decode_block(bytes) {
//         Ok(block) => {
//             let mut certificate_request: CertificateRequest = Default::default();
//             certificate_request.is_encrypted = is_encrypted(&block.headers);
//             if certificate_request.is_encrypted {
//                 // Can't determine details without passphrase
//                 return Ok(certificate_request);
//             }
//             parse_certificate_request(&block.data);
//             Ok(certificate_request)
//         }
//         Err(error) => Err(format!("PEM error: {:?}", error)),
//     }
// }
// fn stringify (ppe: nom_pem::PemParsingError) -> String {
//     format!("{:?}", ppe)
// }

pub fn certificate(bytes: &[u8]) -> Result<Certificate, String> {
    let block: nom_pem::Block =
        // nom_pem::decode_block(bytes).map_err(stringify)?;
        nom_pem::decode_block(bytes).map_err(|ppe| format!("{:?}", ppe))?;
    let xcert = x509_parser::x509_parser(&block.data)
        .to_full_result()
        .map_err(|nie| format!("{:?}", nie))?;
    let tbs = xcert.tbs_certificate().map_err(|nie| format!("{:?}", nie))?;
    let tm_vec = xcert
        .tbs_certificate()
        .and_then(|tbs| tbs.validity())
        // .and_then(|tm_vec| {
        //     tm_vec
        //         .iter()
        //         .nth(1)
        // })
        .map_err(|xe: x509_parser::error::X509Error| format!("{:?}", xe))?;
    let expires: Result<time::Tm, String> =
        tm_vec.into_iter().nth(1).ok_or("Validity Error".into());
    // let expires = expires?;
    // .map_err(|ppe| format!("{:?}", ppe))?;
    return Ok(Certificate::new(tbs.subject().to_string(), expires?));

    // return Err("HEY".into());
    /*
    match nom_pem::decode_block(bytes) {
        Ok(block) => match x509_parser::x509_parser(&block.data) {
            IResult::Done(_unparsed_suffix, xcert) => match xcert.tbs_certificate() {
                Ok(tbs) => {

                    Ok(Certificate2 = Certificate2::new(xcert.subject(), tbs.validity.iter.nth(1)))
                },
                X509Error(error) => Err(format!("{}", error)),
            },
            IResult::Error(error) => Err(format!("{}", error)),
            IResult::Incomplete(needed) => Err(format!("Incomplete parse: {:?}", needed)),
        },
        Err(error) => Err(format!("PEM error: {:?}", error)),
    }
    */}
