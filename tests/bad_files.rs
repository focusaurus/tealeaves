extern crate rsfs;
extern crate tealeaves;
use std::path::Path;
use rsfs::GenFS;

#[test]
fn empty_file_gets_error() {
    let fs = rsfs::mem::unix::FS::new();
    fs.create_dir_all("/tmp").unwrap();
    let empty = fs.create_file("/tmp/empty");

    let file_info = tealeaves::scan(&fs, &"/tmp/empty").unwrap();
    assert!(file_info
                .checks
                .iter()
                .any(|c| format!("{}", c) == "🔥 is empty"));
}
