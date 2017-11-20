use std::{io, fs, path, fmt};
use std::io::BufRead;
use std::path::{PathBuf, Path};

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
            output.push_str(" ");
            output.push_str(&check.message);
            output.push('\n');
        }
        write!(out, "{}\n{}\n", self.path_buf.to_str().unwrap(), output)
    }
}

pub fn scan(path: &Path) -> io::Result<FileInfo> {
    let mut checks: Vec<Check> = vec![];
    let metadata = fs::metadata(path);
    match metadata {
        Ok(metadata) => {
            checks.push(Check::ok("got metadata"));
            if metadata.is_dir() {
                checks.push(Check::ok("is a directory"));
            }
            if metadata.is_file() {
                checks.push(Check::ok("is a file"));
                match metadata.len() {
                    0 => {
                        checks.push(Check::warning("is empty"));
                    },
                    1...4096 => {
                        checks.push(Check::warning("reasonable size"));
                    },
                    _ => {
                        checks.push(Check::warning("too big to be interesting"));
                    },
                }
            }

        },
        Err(error) => {
            match error.kind() {
                io::ErrorKind::NotFound => {
                    checks.push(Check::error("not found"));

                },
                _ => {
                    checks.push(Check::error(&error.to_string()));
                },
            }
        }
    }
    // if !path.exists() {
    //     checks.push(Check::error("Not found"));
    //     return Ok(FileInfo {
    //                   path_buf: path.to_path_buf(),
    //                   checks,
    //               });
    // }
    // if path.is_dir() {
    //     checks.push(Check::ok("is a directory"));
    //     // for entry in fs::read_dir(path)? {
    //     //     let entry = entry?;
    //     //     let path = entry.path();
    //     //     if path.is_dir() {
    //     //         visit_dirs(&path, cb)?;
    //     //     } else {
    //     //         cb(&entry);
    //     //     }
    //     // }
    // }
    // if path.is_file() {
    //     checks.push(Check::ok("is a file"));
    //     match fs::File::open(path) {
    //         Ok(file) => {
    //             let reader = io::BufReader::new(&file);
    //             let line_count = reader.lines().count();
    //             checks.push(Check::ok(&format!("{} lines", line_count)));
    //             let reader = io::BufReader::new(&file);
    //             let first = reader.lines().nth(0);
    //             println!("DEBUG1 {:?}", first);
    //             match first {
    //                 Some(line) => {
    //                     checks.push(Check::ok("has first line"));
    //                 }
    //                 _ => (),
    //             }
    //             // .map(|l| { checks.push(Check::ok("has first line")); });
    //             let reader = io::BufReader::new(&file);
    //             let last = reader.lines().last();
    //             match last {
    //                 Some(line) => {
    //                     checks.push(Check::ok("has last line"));
    //                 }
    //                 _ => (),
    //             }
    //             // .map(|l| { checks.push(Check::ok("has last line")); });
    //
    //         }
    //         Err(error) => {
    //             checks.push(Check::error("Error opening"));
    //         }
    //     }
    // }
    let mut path_buf = PathBuf::new();
    path_buf.push(path);
    Ok(FileInfo {
           path_buf: path_buf,
           checks,
       })
}
