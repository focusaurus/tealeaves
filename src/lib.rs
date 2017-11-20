use std::path::{PathBuf,Path};
use std::{io, path, fmt};

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
enum MessageKind {
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
struct Check {
    kind: MessageKind,
    message: String,
}

impl Check {
    fn error(message: &str) -> Self {
        Self {
            message: message.to_string(),
            kind: MessageKind::Error,
        }
    }
    fn warning(message: &str) -> Self {
        Self {
            message: message.to_string(),
            kind: MessageKind::Warning,
        }
    }
    fn ok(message: &str) -> Self {
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
    path_buf: path::PathBuf,
    checks: Vec<Check>,
}

impl fmt::Display for FileInfo {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        let mut checks = self.checks.to_vec();
        checks.sort();
        for check in checks {
            output.push_str("\t ");
            output.push_str(match check.kind {
                                MessageKind::Error => "🔥",
                                MessageKind::Warning => "⚠️",
                                MessageKind::Ok => "✓",
                            });
            output.push_str(&check.message);
        }
        write!(out, "{}\n{}", self.path_buf.to_str().unwrap(), output)
    }
}

pub fn scan(path: &Path) -> io::Result<FileInfo> {
    let mut checks: Vec<Check> = vec![];
    if !path.exists() {
        checks.push(Check::error("Not found"));
        return Ok(FileInfo {
                      path_buf: path.to_path_buf(),
                      checks,
                  });
    }
    if path.is_dir() {
        checks.push(Check::ok("is a directory"));
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
        checks.push(Check::ok("is a file"));
    }
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    Ok(FileInfo {
           path_buf: path_buf,
           checks,
       })
}
