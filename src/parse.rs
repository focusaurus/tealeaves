// use nom_pem::headers::{HeaderEntry, ProcTypeType};
extern crate nom_pem;
use nom::IResult;
use std::io;

fn public_key<'a>(bytes: &'a [u8]) -> io::Result<&'a [u8]> {
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
        IResult::Done(_input, output) => Ok(output.0),
        IResult::Error(error) => Err(io::Error::new(io::ErrorKind::Other, error)),
        IResult::Incomplete(_needed) => {
            Err(io::Error::new(io::ErrorKind::Other, "Didn't fully parse"))
        }
    }
}

#[test]
fn basics() {
    let algorithm = public_key(&b"ssh-rsa aaaa hey there\n"[..]).unwrap();
    assert_eq!(algorithm, &b"ssh-rsa"[..])
}
