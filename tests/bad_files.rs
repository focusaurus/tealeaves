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
    fs.set_permissions("/tmp/unreadable", Permissions::from_mode(0o200));
    let mode_out = fs.metadata("/tmp/unreadable")
        .unwrap()
        .permissions()
        .mode();

    println!("HEY scanning unreadable mode_out {:o}", mode_out);
    let file_info = tealeaves::scan(&fs, &"/tmp/unreadable").unwrap();
    println!("HEY unreadable: {}", file_info);
    assert!(file_info
                .checks
                .iter()
                .any(|c| format!("{}", c) == "🔥 missing owner read permission"));
}
