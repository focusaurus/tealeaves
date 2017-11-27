extern crate rsfs;
extern crate tealeaves;
use rsfs::GenFS;
use rsfs::unix_ext::PermissionsExt;
use rsfs::mem::unix::Permissions;
use rsfs::Metadata;
use rsfs::unix_ext::FileExt;
use rsfs::mem::unix::FS;
use std::io::Write;

fn memfs1() -> FS {
    let fs = rsfs::mem::unix::FS::new();
    fs.create_dir_all("/tmp").unwrap();
    fs
}

#[test]
fn empty_file_gets_error() {
    let fs = memfs1();
    let empty = fs.create_file("/tmp/empty");
    let file_info = tealeaves::scan(&fs, &"/tmp/empty").unwrap();
    assert!(file_info
                .checks
                .iter()
                .any(|c| format!("{}", c) == "🔥 is empty"));
}

#[test]
fn unreadable_file_gets_error() {
    let fs = memfs1();
    let mut unreadable = fs.create_file("/tmp/unreadable").unwrap();
    unreadable.write(&[1, 2, 3, 4]);
    for &mode in [0o000, 0o002, 0o020, 0o200, 0o222].iter() {
        fs.set_permissions("/tmp/unreadable", Permissions::from_mode(mode));
        let file_info = tealeaves::scan(&fs, &"/tmp/unreadable").unwrap();
        assert!(file_info
                    .checks
                    .iter()
                    .any(|c| format!("{}", c) == "🔥 missing read permission"));

    }
}

#[test]
fn readable_file_gets_no_error() {
    let fs = memfs1();
    let mut readable = fs.create_file("/tmp/readable").unwrap();
    readable.write(&[1, 2, 3, 4]);
    for &mode in [0o004, 0o004, 0o040, 0o400, 0o444].iter() {
        fs.set_permissions("/tmp/readable", Permissions::from_mode(mode));
        let file_info = tealeaves::scan(&fs, &"/tmp/readable").unwrap();
        assert!(file_info
                    .checks
                    .iter()
                    .all(|c| format!("{}", c) != "🔥 missing read permission"));

    }
}

#[test]
fn small_file_gets_error() {
    let fs = memfs1();
    let mut small = fs.create_file("/tmp/small").unwrap();
    small.write(&[1, 2, 3, 4]);
    let file_info = tealeaves::scan(&fs, &"/tmp/small").unwrap();
    assert!(file_info
                .checks
                .iter()
                .any(|c| format!("{}", c) == "🔥 filesize too low"));

}
