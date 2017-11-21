extern crate filesystem;
use filesystem::FileSystem;
use filesystem::UnixFileSystem;
use std::{io, path, fmt};
use std::path::{PathBuf, Path};

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum MessageKind {
    Error,
    Warning,
    Ok,
}

#[test]
fn test_message_kind_order() {
    assert!(MessageKind::Error < MessageKind::Warning);
    assert!(MessageKind::Warning < MessageKind::Ok);
    assert!(MessageKind::Error < MessageKind::Ok);
    assert!(MessageKind::Ok > MessageKind::Warning);
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Check {
    kind: MessageKind,
    message: String,
}

impl fmt::Display for Check {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        output.push_str(match self.kind {
                            MessageKind::Error => "🔥",
                            MessageKind::Warning => "⚠️",
                            MessageKind::Ok => "✓",
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
            kind: MessageKind::Error,
        }
    }
    pub fn warning(message: &str) -> Self {
        Self {
            message: message.to_string(),
            kind: MessageKind::Warning,
        }
    }
    pub fn ok(message: &str) -> Self {
        Self {
            message: message.to_string(),
            kind: MessageKind::Ok,
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

pub fn scan2<F>(fs: &F, path: &Path) -> io::Result<FileInfo>
    where F: FileSystem + UnixFileSystem
{
    let mut checks: Vec<Check> = vec![];
    if fs.is_dir(&path) {
        checks.push(Check::ok("is a directory"));

    }
    if fs.is_file(&path) {
        checks.push(Check::ok("is a file"));
        let mode = fs.mode(path).unwrap();
        let can_read = mode & 0o500 != 0;
        if !can_read {
            checks.push(Check::error("missing read permission"));
        }
    }
    let mut path_buf = PathBuf::new();
    path_buf.push(path);

    Ok(FileInfo { path_buf, checks })
}
