extern crate base64;
extern crate nom_pem;
extern crate rsfs;
extern crate time;
extern crate x509_parser;
pub mod certificate;
pub mod leaf;
pub mod private_key;
pub mod public_key;
pub mod ssh_key;
pub use leaf::Leaf;
use rsfs::unix_ext::*;
use rsfs::*;
use rsfs::{GenFS, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};

#[macro_use(
    call,
    do_parse,
    is_a_s,
    is_a,
    is_not_s,
    is_not,
    length_bytes,
    length_data,
    map,
    named,
    tag,
    take,
    error_position
)]
extern crate nom;

#[macro_use(parse_der_sequence_defined, parse_der_defined, fold_parsers)]
extern crate der_parser;

#[macro_use(error_if)]
extern crate rusticata_macros;

pub fn scan<
    P: Permissions + PermissionsExt,
    M: Metadata<Permissions = P>,
    F: GenFS<Permissions = P, Metadata = M>,
>(
    fs: &F,
    path: &AsRef<Path>,
) -> Result<Leaf, String> {
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    let res = fs.metadata(path);
    if let Err(err) = res {
        return Err(format!(
            "Error reading {}: {}",
            path.as_ref().display(),
            err
        ));
    }
    let meta = res.unwrap();
    if meta.is_dir() {
        return Ok(leaf::Leaf::Directory(path_buf));
    }
    if !meta.is_file() {
        return Ok(leaf::Leaf::Unknown(path_buf));
    }
    if meta.is_empty() {
        return Ok(leaf::Leaf::EmptyFile(path_buf));
    }
    let mode = meta.permissions().mode();
    // https://www.cyberciti.biz/faq/unix-linux-bsd-chmod-numeric-permissions-notation-command/
    if mode & 0o444 == 0 {
        return Ok(leaf::Leaf::UnreadableFile(path_buf));
    }

    match meta.len() {
        0...50 => Ok(leaf::Leaf::SmallFile(path_buf)),
        51...4096 => {
            let open_result = fs.open_file(path);
            if open_result.is_err() {
                return Err(format!(
                    "Error opening {}: {}",
                    path.as_ref().display(),
                    open_result.err().unwrap()
                ));
            }
            let mut file = open_result.unwrap();
            let mut bytes = vec![];
            file.read_to_end(&mut bytes).unwrap();
            if bytes.starts_with(b"ssh-") || bytes.starts_with(b"ecdsa-") {
                return match public_key::parse(&bytes) {
                    Ok(key) => Ok(leaf::Leaf::SshKey(path_buf, key)),
                    Err(error) => Ok(leaf::Leaf::Error(path_buf, error)),
                };
            }
            if bytes.starts_with(b"-----BEGIN CERTIFICATE----") {
                return match certificate::parse(&bytes) {
                    Ok(cert) => Ok(leaf::Leaf::Certificate(path_buf, cert)),
                    Err(error) => Ok(leaf::Leaf::Error(path_buf, error)),
                };
            }
            if bytes.starts_with(b"-----BEGIN ") {
                match private_key::parse(&bytes) {
                    Ok(key) => {
                        return Ok(leaf::Leaf::SshKey(path_buf, key));
                    }
                    Err(message) => {
                        return Err(message);
                    }
                }
            }

            Ok(leaf::Leaf::MediumFile(path_buf))
        }
        _ => Ok(leaf::Leaf::LargeFile(path_buf)),
    }
}
