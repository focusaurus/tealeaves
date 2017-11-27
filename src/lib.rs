extern crate rsfs;
use rsfs::{GenFS, Metadata};
use rsfs::*;
use rsfs::unix_ext::*;
use std::{io, path, fmt};
// use std::io::{Write};
use std::path::{PathBuf, Path};

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum Level {
    Error,
    Warning,
    Ok,
}

#[test]
fn test_message_kind_order() {
    assert!(Level::Error < Level::Warning);
    assert!(Level::Warning < Level::Ok);
    assert!(Level::Error < Level::Ok);
    assert!(Level::Ok > Level::Warning);
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Check {
    level: Level,
    message: String,
}

impl fmt::Display for Check {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        output.push_str(match self.level {
                            Level::Error => "🔥",
                            Level::Warning => "⚠️",
                            Level::Ok => "✓",
                        });
        output.push_str(" ");
        output.push_str(&self.message);
        write!(out, "{}", output)
    }
}

impl Check {
    pub fn error(message: &str) -> Self {
        Self {
            message: message.to_string(),
            level: Level::Error,
        }
    }
    pub fn warning(message: &str) -> Self {
        Self {
            message: message.to_string(),
            level: Level::Warning,
        }
    }
    pub fn ok(message: &str) -> Self {
        Self {
            message: message.to_string(),
            level: Level::Ok,
        }
    }
}

#[test]
fn test_check_order() {
    let error = Check::error("");
    let warning = Check::warning("");
    let ok = Check::ok("");
    assert!(error < warning);
    assert!(warning < ok);
    assert!(ok > warning);
    assert!(ok > error);
}

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
    if meta.is_dir() {
        checks.push(Check::ok("is a directory"));

    }
    if meta.is_file() {
        checks.push(Check::ok("is a file"));
        if meta.is_empty() {
            checks.push(Check::error("is empty"));
        }
        let mode = meta.permissions().mode();
        // https://www.cyberciti.biz/faq/unix-linux-bsd-chmod-numeric-permissions-notation-command/
        let can_read = mode & 0o444 != 0;
        if !can_read {
            checks.push(Check::error("missing read permission"));
        }
        if meta.len() < 50 {
            checks.push(Check::error("filesize too low"));
        }
        if meta.len() > 4096 {
            checks.push(Check::error("filesize too high"));
        }

    }
    let mut path_buf = PathBuf::new();
    path_buf.push(path);

    Ok(FileInfo { path_buf, checks })
}
