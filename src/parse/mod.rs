extern crate base64;
extern crate byteorder;
extern crate nom_pem;
extern crate rsfs;
extern crate yasna;
pub mod private_key;
pub mod public_key;
use byteorder::{BigEndian, ReadBytesExt};
use std::io;
use std::io::{ErrorKind, Read};

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
