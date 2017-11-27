extern crate rsfs;
extern crate tealeaves;
use rsfs::GenFS;
use std::path::PathBuf;
use tealeaves::{Check2, FileInfo};
//
// #[test]
// fn test_file_info_display() {
//     let mut checks = vec![];
//     checks.push(Check::warning("warning 1"));
//     checks.push(Check::ok("ok 1"));
//     checks.push(Check::error("error 1"));
//     checks.push(Check::ok("ok 2"));
//     checks.push(Check::warning("warning 2"));
//     checks.push(Check::error("error 2"));
//     let file_info = FileInfo::new(PathBuf::from("/unit/test"), checks);
//     assert_eq!(format!("{}", file_info),
//                "/unit/test
// \t 🔥 error 1
// \t 🔥 error 2
// \t ⚠️ warning 1
// \t ⚠️ warning 2
// \t ✓ ok 1
// \t ✓ ok 2
// ");
// }
