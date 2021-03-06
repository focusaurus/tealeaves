use base64;
use ssh_key::{peek_algorithm, SshKey};
use nom;

named!(space_sep, is_a_s!(" \t"));
named!(value, is_not_s!(" \t"));
named!(
    nom_public_key<(&[u8], &[u8], &[u8])>,
    do_parse!(
        algorithm: value
            >> _separator: space_sep
            >> payload: value
            >> _separator: space_sep
            >> comment: is_not_s!("\r\n")
            >> (algorithm, payload, comment)
    )
);

pub fn parse(bytes: &[u8]) -> Result<SshKey, String> {
    match nom_public_key(bytes) {
        Ok((_remaining, (_label, payload, comment))) => {
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
        Err(nom::Err::Error(_e)) | Err(nom::Err::Failure(_e)) => Err("Parse error".into()),
        Err(nom::Err::Incomplete(_needed)) => Err("Didn't fully parse".into()),
    }
}
