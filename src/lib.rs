extern crate base64;
extern crate nom_pem;
extern crate rsfs;
pub mod file_info;
pub mod parse;
pub use file_info::FileInfo;
use rsfs::{GenFS, Metadata};
use rsfs::*;
use rsfs::unix_ext::*;
use std::io::Read;
use std::path::{Path, PathBuf};

#[macro_use(call, do_parse, error_position, is_a_s, is_a, is_not_s, is_not, length_bytes,
            length_data, map, named, tag, take)]
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
) -> Result<FileInfo, String> {
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    let res = fs.metadata(path);
    // Todo match here instead of is_err
    if res.is_err() {
        return Err(format!(
            "Error reading {}: {}",
            path.as_ref().display(),
            res.err().unwrap()
        ));
    }
    let meta = res.unwrap();
    if meta.is_dir() {
        return Ok(file_info::FileInfo::Directory(path_buf));
    }
    if !meta.is_file() {
        return Ok(file_info::FileInfo::Unknown(path_buf));
    }
    if meta.is_empty() {
        return Ok(file_info::FileInfo::EmptyFile(path_buf));
    }
    let mode = meta.permissions().mode();
    // https://www.cyberciti.biz/faq/unix-linux-bsd-chmod-numeric-permissions-notation-command/
    if mode & 0o444 == 0 {
        return Ok(file_info::FileInfo::UnreadableFile(path_buf));
    }

    match meta.len() {
        0...50 => Ok(file_info::FileInfo::SmallFile(path_buf)),
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
                return match parse::public_key(&bytes) {
                    Ok(key) => Ok(file_info::FileInfo::SshKey(path_buf, key)),
                    Err(error) => Ok(file_info::FileInfo::Error(path_buf, error)),
                };
            }
            if bytes.starts_with(b"-----BEGIN CERTIFICATE REQUEST----") {
                return Ok(file_info::FileInfo::TlsCertificate(path_buf));
                // TODO parse it
                // match parse::certificate_request(&bytes) {
                //     Ok(req) => file_info.certificate_request = Some(req),
                //     Err(message) => file_info.error = Some(message),
                // }
                // if file_info.certificate_request.is_some() {
                //     file_info.is_pem = true;
                // }
            }
            if bytes.starts_with(b"-----BEGIN ") {
                match parse::private_key(&bytes) {
                    Ok(key) => {
                        return Ok(file_info::FileInfo::SshKey(path_buf, key));
                    }
                    Err(message) => {
                        return Err(message);
                    }
                }
            }

            Ok(file_info::FileInfo::MediumFile(path_buf))
        }
        _ => Ok(file_info::FileInfo::LargeFile(path_buf)),
    }
}
