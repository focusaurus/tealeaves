extern crate rsfs;
extern crate tealeaves;
use rsfs::GenFS;
use rsfs::mem::unix::FS;
use rsfs::mem::unix::Permissions;
use rsfs::unix_ext::PermissionsExt;
use std::io::Write;
use tealeaves::check::Kind;

fn memfs() -> FS {
    let fs = rsfs::mem::unix::FS::new();
    fs.create_dir_all("/tmp").unwrap();
    fs
}

#[test]
fn empty_file_gets_error() {
    let fs = memfs();
    let empty = fs.create_file("/tmp/empty");
    let file_info = tealeaves::scan(&fs, &"/tmp/empty").unwrap();
    assert!(file_info
                .checks
                .iter()
                .any(|c| c.kind == Kind::Empty));
}

#[test]
fn unreadable_file_gets_error() {
    let fs = memfs();
    let mut unreadable = fs.create_file("/tmp/unreadable").unwrap();
    unreadable.write(&[1, 2, 3, 4]);
    for &mode in [0o000, 0o002, 0o020, 0o200, 0o222].iter() {
        fs.set_permissions("/tmp/unreadable", Permissions::from_mode(mode));
        let file_info = tealeaves::scan(&fs, &"/tmp/unreadable").unwrap();
        assert!(file_info
                    .checks
                    .iter()
                    .any(|c| c.kind == Kind::Unreadable));

    }
}

#[test]
fn readable_file_gets_no_error() {
    let fs = memfs();
    let mut readable = fs.create_file("/tmp/readable").unwrap();
    readable.write(&[1, 2, 3, 4]);
    for &mode in [0o004, 0o004, 0o040, 0o400, 0o444].iter() {
        fs.set_permissions("/tmp/readable", Permissions::from_mode(mode));
        let file_info = tealeaves::scan(&fs, &"/tmp/readable").unwrap();
        assert!(!file_info
                     .checks
                     .iter()
                     .any(|c| c.kind == Kind::Unreadable));
    }
}

#[test]
fn low_size_gets_error() {
    let fs = memfs();
    let mut small = fs.create_file("/tmp/small").unwrap();
    small.write(&[1, 2, 3, 4]);
    let file_info = tealeaves::scan(&fs, &"/tmp/small").unwrap();
    assert!(file_info
                .checks
                .iter()
                .any(|c| c.kind == Kind::TooSmall));

}

#[test]
fn not_pem_gets_detected() {
    let fs = memfs();
    let mut not_pem = fs.create_file("/tmp/not_pem").unwrap();
    not_pem.write(b"Hi this is not even a PEM file or anything, but it's long enough to maybe");
    let file_info = tealeaves::scan(&fs, &"/tmp/not_pem").unwrap();
    assert!(file_info
                .checks
                .iter()
                .any(|c| c.kind == Kind::NotPEM));
}

#[test]
fn pem_gets_detected() {
    let fs = memfs();
    let mut pem = fs.create_file("/tmp/pem").unwrap();
    pem.write(b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA2WS+xYVACuTmyxQDByFfD5tRfZFnxq03l04+tYPxExgAAAKj+L4az/i+G
swAAAAtzc2gtZWQyNTUxOQAAACA2WS+xYVACuTmyxQDByFfD5tRfZFnxq03l04+tYPxExg
AAAEBIhgNOlzPnH3cAul5S0VSrnirdVr6TVDL2gVDXIEu6FTZZL7FhUAK5ObLFAMHIV8Pm
1F9kWfGrTeXTj61g/ETGAAAAH1RlYWxldmVzIHRlc3QgRUQyNTUxOSBTU0ggS2V5IDEBAg
MEBQY=
-----END OPENSSH PRIVATE KEY-----
");
    let file_info = tealeaves::scan(&fs, &"/tmp/pem").unwrap();
    assert!(file_info
                .checks
                .iter()
                .any(|c| c.kind == Kind::PEM));
}

#[test]
fn high_size_gets_error() {
    let fs = memfs();
    let mut big = fs.create_file("/tmp/big").unwrap();
    for x in 0..1024 {
        big.write(&[1, 2, 3, 4, 5, 6, 7]);
    }
    let file_info = tealeaves::scan(&fs, &"/tmp/big").unwrap();
    assert!(file_info
                .checks
                .iter()
                .any(|c| match c.kind {
                         Kind::TooBig => true,
                         _ => false,
                     }));

}
