// use nom_pem::headers::{HeaderEntry, ProcTypeType};
extern crate base64;
extern crate nom_pem;
use nom::IResult;
use std::io;

#[derive(Debug)]
struct PublicKey {
    algorithm: Option<String>,
    comment: Option<String>,
    payload: Option<Vec<u8>>
}

fn public_key<'a>(bytes: &'a [u8]) -> io::Result<PublicKey> {
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

            Ok(PublicKey{
                algorithm: Some(String::from_utf8_lossy(output.0).into_owned()),
                comment: Some(String::from_utf8_lossy(output.2).into_owned()),
                payload,
            })
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