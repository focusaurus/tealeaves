use std::path::{Path, PathBuf};
use std::{fs, io, path,fmt};

#[derive(Debug)]
enum MessageKind {
    Ok,
    Warning,
    Error,
}

#[derive(Debug)]
struct Check {
    kind: MessageKind,
    message: String,
}

#[derive(Debug)]
pub struct FileInfo {
    path_buf: path::PathBuf,
    checks: Vec<Check>,
}

impl fmt::Display for FileInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "FILE: {} {}", self.path_buf.to_str().unwrap(), self.checks.len())
    }
}

fn ok(message: &str) -> Check {
    Check {
        kind: MessageKind::Ok,
        message: message.to_string(),
    }
}

fn warning(message: &str) -> Check {
    Check {
        kind: MessageKind::Warning,
        message: message.to_string(),
    }
}

fn error(message: &str) -> Check {
    Check {
        kind: MessageKind::Error,
        message: message.to_string(),
    }
}

pub fn scan(path: &Path) -> io::Result<FileInfo> {
    let mut checks: Vec<Check> = vec![];
    if !path.exists() {
        checks.push(error("Not found"));
        return Ok(FileInfo {
                      path_buf: path.to_path_buf(),
                      checks,
                  });
    }
    if path.is_dir() {
        checks.push(ok("is a directory"));
        // for entry in fs::read_dir(path)? {
        //     let entry = entry?;
        //     let path = entry.path();
        //     if path.is_dir() {
        //         visit_dirs(&path, cb)?;
        //     } else {
        //         cb(&entry);
        //     }
        // }
    } else {
        checks.push(ok("is a file"));
    }
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    Ok(FileInfo {
           path_buf: path_buf,
           checks,
       })
}
