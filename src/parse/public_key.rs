extern crate base64;
use file_info;
use parse;
use nom::IResult;
use std::io;

#[derive(Debug)]
pub struct PublicKey<'a> {
    pub algorithm: &'a [u8],
    pub comment: &'a [u8],
    pub payload: Option<Vec<u8>>,
}

pub fn public_key<'a>(bytes: &'a [u8]) -> io::Result<PublicKey> {
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
        IResult::Done(_input, output) => {
            let result = base64::decode(output.1);
            let mut payload = None;
            if let Ok(decoded) = result {
                payload = Some(decoded);
            }

            Ok(PublicKey {
                   algorithm: output.0,
                   comment: output.2,
                   payload,
               })
        }
        IResult::Error(error) => Err(io::Error::new(io::ErrorKind::Other, error)),
        IResult::Incomplete(_needed) => {
            Err(io::Error::new(io::ErrorKind::Other, "Didn't fully parse"))
        }
    }
}

#[test]
fn basics() {
    let key = public_key(&b"ssh-rsa aaaa hey there\n"[..]).unwrap();
    assert_eq!(key.algorithm, &b"ssh-rsa"[..]);
}


pub fn ed25519(bytes: &[u8]) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    let pub_key = public_key(bytes)?;
    let comment = String::from_utf8(Vec::from(pub_key.comment)).unwrap();
    ssh_key.comment = Some(comment);
    if let Some(payload) = pub_key.payload {
        let mut reader = io::BufReader::new(payload.as_slice());

        let algorithm = parse::read_field(&mut reader).unwrap_or(vec![]);
        ssh_key.point = Some(parse::read_field(&mut reader).unwrap_or(vec![]));
        if let Ok(algo) = String::from_utf8(algorithm.clone()) {
            ssh_key.algorithm = Some(algo);
        }
        if parse::has_prefix(b"ssh-ed25519", pub_key.algorithm) {
            ssh_key.algorithm = Some("ed25519".to_string());
        }
    }
    Ok(ssh_key)
}

pub fn rsa(bytes: &[u8]) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    let pub_key = public_key(bytes)?;
    if pub_key.algorithm == &b"ssh-rsa"[..] {
        ssh_key.algorithm = Some("rsa".to_string());
    }
    let comment = String::from_utf8(Vec::from(pub_key.comment)).unwrap();
    ssh_key.comment = Some(comment);
    if let Some(payload) = pub_key.payload {
        let mut reader = io::BufReader::new(payload.as_slice());
        let algorithm = parse::read_field(&mut reader).unwrap_or(vec![]);
        let _exponent = parse::read_field(&mut reader).unwrap_or(vec![]);
        let modulus = parse::read_field(&mut reader).unwrap_or(vec![]);
        // modulus has a leading zero byte to be discarded, then just convert bytes to bits
        ssh_key.key_length = Some((modulus.len() - 1) * 8);
        if let Ok(algo) = String::from_utf8(algorithm.clone()) {
            ssh_key.algorithm = Some(algo);
        }
    }
    Ok(ssh_key)
}

pub fn dsa(bytes: &[u8]) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    ssh_key.algorithm = Some("dsa".to_string());
    let pub_key = public_key(bytes)?;
    let comment = String::from_utf8(Vec::from(pub_key.comment)).unwrap();
    ssh_key.comment = Some(comment);
    if let Some(payload) = pub_key.payload {
        let mut reader = io::BufReader::new(payload.as_slice());
        let algorithm = parse::read_field(&mut reader).unwrap_or(vec![]);
        if algorithm == &b"ssh-dss"[..] {
            ssh_key.algorithm = Some("dsa".to_string());
        }
        let field = parse::read_field(&mut reader).unwrap_or(vec![]);
        // field has a leading zero byte to be discarded, then just convert bytes to bits
        ssh_key.key_length = Some((field.len() - 1) * 8);
    }
    Ok(ssh_key)
}

pub fn ecdsa(bytes: &[u8]) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    ssh_key.algorithm = Some("ecdsa".to_string());
    let pub_key = public_key(bytes)?;
    let comment = String::from_utf8(Vec::from(pub_key.comment)).unwrap();
    ssh_key.comment = Some(comment);
    if let Some(payload) = pub_key.payload {
        let mut reader = io::BufReader::new(payload.as_slice());
        let algorithm = parse::read_field(&mut reader).unwrap_or(vec![]);
        if algorithm.ends_with(b"-nistp256") {
            ssh_key.key_length = Some(256);
        }
        if algorithm.ends_with(b"-nistp384") {
            ssh_key.key_length = Some(384);
        }
        if algorithm.ends_with(b"-nistp521") {
            ssh_key.key_length = Some(521);
        }
    }
    Ok(ssh_key)
}
