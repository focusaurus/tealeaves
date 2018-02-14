use base64;
use der_parser::oid::Oid;
use nom_pem;
use nom_pem::{HeaderEntry, ProcTypeType};
use nom::IResult;
use ssh_key::{Algorithm, SshKey, peek_algorithm};
use std::fmt;
use der_parser::{der_read_element_content_as, parse_der_implicit, parse_der_integer,
                 parse_der_octetstring, DerObject, DerObjectContent, DerTag};

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

named!(space_sep, is_a_s!(" \t"));
named!(value, is_not_s!(" \t"));
named!(
    nom_public_key<(&[u8], &[u8], &[u8])>,
    do_parse!(
        algorithm: value >> separator: space_sep >> payload: value >> separator: space_sep
            >> comment: is_not_s!("\r\n") >> (algorithm, payload, comment)
    )
);

pub fn parse(bytes: &[u8]) -> Result<SshKey, String> {
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
