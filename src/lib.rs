// use std::io::{Write};
extern crate rsfs;
mod check;
mod level;
pub use check::Check;
pub use level::Level;
use rsfs::{GenFS, Metadata};
use rsfs::*;
use rsfs::unix_ext::*;
use std::{io, path, fmt};
use std::path::{PathBuf, Path};


#[derive(Debug)]
pub struct FileInfo {
    pub path_buf: path::PathBuf,
    pub checks: Vec<Check>,
}

impl FileInfo {
    pub fn new(path_buf: PathBuf, checks: Vec<Check>) -> Self {
        FileInfo { path_buf, checks }
    }
}

impl fmt::Display for FileInfo {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        let mut checks = self.checks.to_vec();
        checks.sort();
        for check in checks {
            output.push_str(&format!("\t {}\n", check));
        }
        write!(out, "{}\n{}", self.path_buf.to_str().unwrap(), output)
    }
}

pub fn scan<P: Permissions + PermissionsExt,
            M: Metadata<Permissions = P>,
            F: GenFS<Permissions = P, Metadata = M>>
    (fs: &F,
     path: &AsRef<Path>)
     -> io::Result<FileInfo> {
    let mut checks: Vec<Check> = vec![];
    let meta = fs.metadata(path).unwrap();
    // if meta.is_dir() {
    //     checks.push(Check::ok("is a directory"));
    //
    // }
    if meta.is_file() {
        // checks.push(Check::ok("is a file"));
        if meta.is_empty() {
            checks.push(Check::Empty(Level::Error, "is empty".to_string()));
        }
        let mode = meta.permissions().mode();
        // https://www.cyberciti.biz/faq/unix-linux-bsd-chmod-numeric-permissions-notation-command/
        let can_read = mode & 0o444 != 0;
        if !can_read {
            checks.push(Check::Unreadable(Level::Error, "missing read permission".to_string()));
        }
        if meta.len() < 50 {
            checks.push(Check::TooSmall(Level::Error, "filesize too low".to_string()));
        }
        if meta.len() > 4096 {
            checks.push(Check::TooBig(Level::Error, "filesize too high".to_string()));
        }

    }
    let mut path_buf = PathBuf::new();
    path_buf.push(path);

    Ok(FileInfo { path_buf, checks })
}
