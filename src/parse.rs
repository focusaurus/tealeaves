extern crate nom_pem;
// use nom_pem::headers::{HeaderEntry, ProcTypeType};
use nom::IResult;

fn public_key<'a>(bytes: &'a [u8]) -> &'a [u8] {
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
        IResult::Done(_input, output) => output.0,
        IResult::Error(_error) => &b"error"[..],
        IResult::Incomplete(_needed) => &b"incomplete"[..],
    }
}

#[test]
fn basics() {
    let algorithm = public_key(&b"ssh-rsa aaaa hey there\n"[..]);
    assert_eq!(algorithm, &b"ssh-rsa"[..])
}
