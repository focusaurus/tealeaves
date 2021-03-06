use der_parser::oid::Oid;
use der_parser::{
    der_read_element_content_as, parse_der_implicit, parse_der_integer, parse_der_octetstring,
    DerObject, DerObjectContent, DerTag, DER_OBJ_TOOSHORT,
};
use nom;
use nom::IResult;
use nom_pem;
use nom_pem::{HeaderEntry, ProcTypeType};
use ssh_key::{peek_algorithm, Algorithm, SshKey};

// My code does not directly use these names. Why do I need to `use` them?
use nom::be_u32;

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
        Ok((_unparsed_suffix, der)) => {
            assert_eq!(_unparsed_suffix.len(), 0);
            let der_objects = der.as_sequence().unwrap();
            let p_integer = der_objects[1].content.as_slice().unwrap();
            // strip leading null byte
            let p_integer = &p_integer[1..];
            Ok(Algorithm::Dsa(p_integer.to_owned()))
        }
        Err(nom::Err::Error(error)) | Err(nom::Err::Failure(error)) => Err(format!("{:?}", error)),
        Err(nom::Err::Incomplete(needed)) => Err(format!("Incomplete parse: {:?}", needed)),
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
        Ok((_unparsed_suffix, der)) => {
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
        Err(nom::Err::Error(error)) => Err(format!("{:?}", error)),
        Err(nom::Err::Failure(error)) => Err(format!("{:?}", error)),
        Err(nom::Err::Incomplete(needed)) => Err(format!("Incomplete parse: {:?}", needed)),
    }
}

fn der_read_oid_content(i: &[u8], _tag: u8, len: usize) -> IResult<&[u8], DerObjectContent> {
    der_read_element_content_as(i, DerTag::Oid as u8, len)
}

fn der_read_bitstring_content(i: &[u8], _tag: u8, len: usize) -> IResult<&[u8], DerObjectContent> {
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
        Ok((_unparsed_suffix, der)) => {
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
            Ok(Algorithm::Unknown)
        }
        Err(nom::Err::Failure(error)) => Err(format!("{:?}", error)),
        Err(nom::Err::Error(error)) => Err(format!("{:?}", error)),
        Err(nom::Err::Incomplete(needed)) => Err(format!("Incomplete parse: {:?}", needed)),
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
        tag!(b"openssh-key-v1\0")
            >> cipher_name: length_bytes!(be_u32)
            >> _kdf_name: length_bytes!(be_u32)
            >> _kdf_options: length_bytes!(be_u32)
            >> _key_count: tag!(&[0, 0, 0, 1])
            >> key: length_bytes!(be_u32)
            >> (cipher_name, key)
    )
);

fn openssh_key_v1_private(bytes: &[u8]) -> Result<SshKey, String> {
    match nom_openssh_key_v1_private(bytes) {
        Ok((_tail, (cipher_name, key_bytes))) => {
            let mut ssh_key: SshKey = Default::default();
            ssh_key.is_encrypted = cipher_name != b"none";
            match peek_algorithm(ssh_key.is_encrypted, key_bytes) {
                Ok(algorithm) => {
                    ssh_key.algorithm = algorithm;
                    Ok(ssh_key)
                }
                Err(message) => Err(message),
            }
        }
        Err(nom::Err::Error(_error)) | Err(nom::Err::Failure(_error)) => Err("Parse error".into()),
        Err(nom::Err::Incomplete(_needed)) => Err("Didn't fully parse".into()),
    }
}

pub fn parse(bytes: &[u8]) -> Result<SshKey, String> {
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
