extern crate base64;
extern crate byteorder;
extern crate nom_pem;
extern crate rsfs;
extern crate yasna;
pub mod file_info;
pub mod parse;
use file_info::FileInfo;
use rsfs::{GenFS, Metadata};
use rsfs::*;
use rsfs::unix_ext::*;
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};

#[macro_use]
extern crate nom;

pub fn scan<
    P: Permissions + PermissionsExt,
    M: Metadata<Permissions = P>,
    F: GenFS<Permissions = P, Metadata = M>,
>(
    fs: &F,
    path: &AsRef<Path>,
) -> io::Result<FileInfo> {
    let mut file_info = FileInfo::new();
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    file_info.path_buf = path_buf;
    let meta = fs.metadata(path)?;
    file_info.is_directory = meta.is_dir();
    file_info.is_file = meta.is_file();

    if file_info.is_file {
        let mode = meta.permissions().mode();
        file_info.mode = Some(mode);
        // https://www.cyberciti.biz/faq/unix-linux-bsd-chmod-numeric-permissions-notation-command/
        file_info.is_readable = mode & 0o444 != 0;
    }
    if file_info.is_readable {
        match meta.len() {
            0...50 => {
                file_info.size = file_info::Size::Small;
            }
            51...4096 => {
                file_info.size = file_info::Size::Medium;
            }
            _ => {
                file_info.size = file_info::Size::Large;
            }
        }
    }
    if file_info.size == file_info::Size::Medium {
        let mut file = fs.open_file(path)?;
        let mut bytes = vec![];
        file.read_to_end(&mut bytes).unwrap();
        if bytes.starts_with(b"ssh-ed25519 ") {
            file_info.ssh_key = Some(parse::public_key(&bytes)?);
        }
        if bytes.starts_with(b"ssh-rsa ") {
            file_info.ssh_key = Some(parse::public_key(&bytes)?);
        }
        if bytes.starts_with(b"ssh-dss ") {
            file_info.ssh_key = Some(parse::public_key(&bytes)?);
        }
        if bytes.starts_with(b"ecdsa-sha2-nistp") {
            file_info.ssh_key = Some(parse::public_key(&bytes)?);
        }
        if bytes.starts_with(b"-----BEGIN ") {
            match parse::private_key(&bytes) {
                Ok(key) => file_info.ssh_key = Some(key),
                Err(message) => file_info.error = Some(message),
            }
            if file_info.ssh_key.is_some() {
                file_info.is_pem = true;
            }
        }
    }
    Ok(file_info)
}
