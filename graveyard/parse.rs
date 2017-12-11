extern crate base64;
extern crate nom_pem;
use nom::IResult;
use std::io;

extern crate byteorder;
extern crate rsfs;
extern crate yasna;
use byteorder::{BigEndian, ReadBytesExt};
use nom_pem::headers::{HeaderEntry, ProcTypeType};

#[macro_use]
extern crate nom;

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

fn identify_dsa_public(bytes: &[u8]) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    ssh_key.algorithm = Some("dsa".to_string());
    let pub_key = parse::public_key(bytes)?;
    let comment = String::from_utf8(Vec::from(pub_key.comment)).unwrap();
    ssh_key.comment = Some(comment);
    if let Some(payload) = pub_key.payload {
        let mut reader = io::BufReader::new(payload.as_slice());
        let algorithm = read_field(&mut reader).unwrap_or(vec![]);
        if algorithm == &b"ssh-dss"[..] {
            ssh_key.algorithm = Some("dsa".to_string());
        }
        let field = read_field(&mut reader).unwrap_or(vec![]);
        // field has a leading zero byte to be discarded, then just convert bytes to bits
        ssh_key.key_length = Some((field.len() - 1) * 8);
    }
    Ok(ssh_key)
}

fn identify_ecdsa_public1(content: &str) -> io::Result<file_info::SshKey> {
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

fn identify_ecdsa_public(bytes: &[u8]) -> io::Result<file_info::SshKey> {
    let mut ssh_key = file_info::SshKey::new();
    ssh_key.is_public = true;
    ssh_key.algorithm = Some("ecdsa".to_string());
    let pub_key = parse::public_key(bytes)?;
    let comment = String::from_utf8(Vec::from(pub_key.comment)).unwrap();
    ssh_key.comment = Some(comment);
    if let Some(payload) = pub_key.payload {
        let mut reader = io::BufReader::new(payload.as_slice());
        let algorithm = read_field(&mut reader).unwrap_or(vec![]);
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
