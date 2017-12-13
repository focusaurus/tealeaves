extern crate byteorder;
pub mod private_key;
pub mod public_key;

use byteorder::{BigEndian, ReadBytesExt};
use std::io;
use std::io::{ErrorKind, Read};
use base64;
use file_info;
use nom::IResult;

fn bail(message: String) -> io::Error {
    return io::Error::new(ErrorKind::Other, message);
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


pub fn public_key<'a>(bytes: &'a [u8]) -> io::Result<file_info::SshKey> {
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
        IResult::Done(_input, (algorithm, payload, comment)) => {
            let mut ssh_key = file_info::SshKey::new();
            ssh_key.is_public = true;
            ssh_key.algorithm = Some(String::from_utf8_lossy(&algorithm).into_owned());
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

// #[test]
// fn basics() {
//     let key = public_key(&b"ssh-rsa aaaa hey there\n"[..]).unwrap();
//     assert_eq!(key.algorithm, &b"ssh-rsa"[..]);
// }

fn bit_count(field: Vec<u8>) -> usize {
    // exclude leading null byte then convert bytes to bits
    (field.len() - 1) * 8
}

fn algo_and_length(ssh_key: &mut file_info::SshKey, bytes: &[u8]) {
    let mut reader = io::BufReader::new(bytes);
    let algorithm = read_field(&mut reader).unwrap_or(vec![]);
    match algorithm.as_slice() {
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
        b"ssh-ed25519" => {
            ssh_key.algorithm = Some("ed25519".to_string());
        }
        b"ssh-dss" => {
            ssh_key.algorithm = Some("dsa".to_string());
            let int1 = read_field(&mut reader).unwrap_or(vec![]);
            ssh_key.key_length = Some(bit_count(int1));
        }
        b"ssh-rsa" => {
            ssh_key.algorithm = Some("rsa".to_string());
            let _exponent = read_field(&mut reader).unwrap_or(vec![]);
            let modulus = read_field(&mut reader).unwrap_or(vec![]);
            ssh_key.key_length = Some(bit_count(modulus));
        }
        _ => (),
    }
}
