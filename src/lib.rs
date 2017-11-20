use std::path::{Path, PathBuf};
use std::{cmp, fs, io, path, fmt};

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
enum MessageKind {
    Error,
    Warning,
    Ok,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
struct Check {
    kind: MessageKind,
    message: String,
}
//
// impl PartialOrd for Check {
//     fn partial_cmp(&self, other: &Check) -> Option<cmp::Ordering> {
//         Some(self.kind.cmp(&other.kind))
//     }
// }
// impl PartialEq for Check {
//     fn eq(&self, other: &Check) -> bool {
//         self.kind == other.kind && self.message == other.message
//     }
// }
//
// impl Ord for Check {
//     fn cmp(&self, other: &Check) -> cmp::Ordering {
//         match (self.kind, other.kind) {
//             (MessageKind::Error, MessageKind::Error) => Some(cmp::Ordering::Same),
//             (MessageKind::Error, MessageKind::Warning) => Some(cmp::Ordering::Greater),
//             (MessageKind::Error, MessageKind::Ok) => Some(cmp::Ordering::Greater),
//             (MessageKind::Warning, MessageKind::Error) => Some(cmp::Ordering::Less),
//             (MessageKind::Warning, MessageKind::Warning) => Some(cmp::Ordering::Same),
//             (MessageKind::Warning, MessageKind::Ok) => Some(cmp::Ordering::Greater),
//             (MessageKind::Ok, MessageKind::Error) => Some(cmp::Ordering::Greater),
//             (MessageKind::Ok, MessageKind::Warning) => Some(cmp::Ordering::Less),
//             (MessageKind::Ok, MessageKind::Ok) => Some(cmp::Ordering::Same),
//         }
//         // self.height.cmp(&other.height)
//     }
// }
//
// impl PartialEq for Check {
//     fn eq(&self, other: &Check) -> bool {
//         self.kind == other.kind && self.message == other.message
//     }
// }
//
// impl Eq for Check {
//     fn eq(&self, other: &Check) -> bool {
//         self.kind == other.kind && self.message == other.message
//     }
// }
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
