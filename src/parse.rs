// use nom_pem::headers::{HeaderEntry, ProcTypeType};
// extern crate base64;
extern crate nom_pem;
use file_info;
use nom::IResult;
use std::io;

fn public_key<'a>(bytes: &'a [u8]) -> io::Result<file_info::SshKey> {
    named!(space_sep, is_a_s!(" \t"));
    named!(value, is_not_s!(" \t"));
    named!(pubkey_b<(&[u8], &[u8], &[u8])>,
      do_parse!(
        algorithm: value >>
        separator: space_sep >>
        payload: value >>
        separator: space_sep >>
        comment: is_not_s!("\r\n") >>
        (algorithm, payload, comment)
      )
    );
    match pubkey_b(bytes) {
        IResult::Done(_input, output) => {
            let mut key = file_info::SshKey::new();
            key.algorithm = Some(String::from_utf8_lossy(output.0).into_owned());
            key.comment = Some(String::from_utf8_lossy(output.2).into_owned());
            Ok(key)
        },
        IResult::Error(error) => Err(io::Error::new(io::ErrorKind::Other, error)),
        IResult::Incomplete(_needed) => {
            Err(io::Error::new(io::ErrorKind::Other, "Didn't fully parse"))
        }
    }
}

#[test]
fn basics() {
    let key = public_key(&b"ssh-rsa aaaa hey there\n"[..]).unwrap();
    assert_eq!(key.algorithm.unwrap(), "ssh-rsa");
}
