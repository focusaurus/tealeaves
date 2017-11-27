extern crate rsfs;
extern crate tealeaves;
use std::path::PathBuf;
use tealeaves::{Check, FileInfo, Level};

#[test]
fn test_file_info_display() {
    let mut checks = vec![];
    checks.push(Check::too_big());
    checks.push(Check::empty());
    checks.push(Check::too_small());
    checks.push(Check::unreadable());
    let file_info = FileInfo::new(PathBuf::from("/unit/test"), checks);
    assert_eq!(format!("{}", file_info),
               "/unit/test
\t 🔥 is empty
\t 🔥 missing read permission
\t ⚠️ file size too small
\t ⚠️ file size too big
");
}
