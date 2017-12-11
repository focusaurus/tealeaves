extern crate base64;
extern crate hex;
extern crate rsfs;
extern crate tealeaves;
use rsfs::GenFS;
use rsfs::mem::unix::FS;
use rsfs::mem::unix::Permissions;
use rsfs::unix_ext::PermissionsExt;
use std::io::Write;

fn memfs() -> FS {
    let fs = rsfs::mem::unix::FS::new();
    fs.create_dir_all("/tmp").unwrap();
    fs
}

#[test]
fn empty_file_gets_error() {
    let fs = memfs();
    let _empty = fs.create_file("/tmp/empty");
    let file_info = tealeaves::scan(&fs, &"/tmp/empty").unwrap();
    assert!(file_info.is_size_small);
    assert!(!file_info.is_size_medium);
    assert!(!file_info.is_size_large);
}

#[test]
fn unreadable_file_gets_error() {
    let fs = memfs();
    let mut unreadable = fs.create_file("/tmp/unreadable").unwrap();
    unreadable.write(&[1, 2, 3, 4]).unwrap();
    for &mode in [0o000, 0o002, 0o020, 0o200, 0o222].iter() {
        fs.set_permissions("/tmp/unreadable", Permissions::from_mode(mode))
            .unwrap();
        let file_info = tealeaves::scan(&fs, &"/tmp/unreadable").unwrap();
        assert!(!file_info.is_readable);
    }
}

#[test]
fn readable_file_gets_no_error() {
    let fs = memfs();
    let mut readable = fs.create_file("/tmp/readable").unwrap();
    readable.write(&[1, 2, 3, 4]).unwrap();
    for &mode in [0o004, 0o004, 0o040, 0o400, 0o444].iter() {
        fs.set_permissions("/tmp/readable", Permissions::from_mode(mode))
            .unwrap();
        let file_info = tealeaves::scan(&fs, &"/tmp/readable").unwrap();
        assert!(file_info.is_readable);
    }
}

#[test]
fn low_size_gets_error() {
    let fs = memfs();
    let mut small = fs.create_file("/tmp/small").unwrap();
    small.write(&[1, 2, 3, 4]).unwrap();
    let file_info = tealeaves::scan(&fs, &"/tmp/small").unwrap();
    assert!(file_info.is_size_small);
}

#[test]
fn not_pem_gets_detected() {
    let fs = memfs();
    let mut not_pem = fs.create_file("/tmp/not_pem").unwrap();
    not_pem
        .write(b"Hi this is not even a PEM file or anything, but it's long enough to maybe")
        .unwrap();
    let file_info = tealeaves::scan(&fs, &"/tmp/not_pem").unwrap();
    assert!(!file_info.is_pem);
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
")
        .unwrap();
    let file_info = tealeaves::scan(&fs, &"/tmp/pem").unwrap();
    assert!(file_info.is_pem);
}

#[test]
fn high_size_gets_error() {
    let fs = memfs();
    let mut big = fs.create_file("/tmp/big").unwrap();
    for _x in 0..1024 {
        big.write(&[1, 2, 3, 4, 5, 6, 7]).unwrap();
    }
    let file_info = tealeaves::scan(&fs, &"/tmp/big").unwrap();
    assert!(file_info.is_size_large);
    assert!(!file_info.is_size_small);
    assert!(!file_info.is_size_medium);
}


#[test]
fn pem_long_field_gets_detected() {
    let fs = memfs();
    let mut pem = fs.create_file("/tmp/pem-too-long-field").unwrap();
    // Here's the hex of the start of a valid openssh-key-v1, but the first field length
    // is 4097 (00001001 in hex) which is above 4096 safe limit we will read
    let valid_prefix = "6f70656e7373682d6b65792d763100";
    //    4097 length:  00001001
    let bogus_length = "00001001";
    let bin = hex::decode([valid_prefix, bogus_length].concat()).unwrap();
    let base64 = base64::encode(&bin);
    pem.write(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
        .unwrap();
    pem.write(base64.as_bytes()).unwrap();
    pem.write(b"\n").unwrap();
    pem.write(b"-----END OPENSSH PRIVATE KEY-----\n")
        .unwrap();
    let result = tealeaves::scan(&fs, &"/tmp/pem-too-long-field");
    assert!(result.is_ok());
    assert!(result
                .unwrap()
                .error
                .unwrap()
                .contains("Field size too large"));
}

#[test]
fn asn1_error_gets_detected() {
    let fs = memfs();
    let mut pem = fs.create_file("/tmp/pem").unwrap();
    let mut payload = vec![0];
    payload.extend_from_slice(b"ssh-rsa"); // magic prefix
    payload.extend_from_slice(&[0]); // null byte
    payload.extend_from_slice(b"this-is-not-asn1");
    let tags = ["RSA", "DSA", "EC"];
    for tag in tags.iter() {
        let payload = base64::encode(&payload);
        pem.write(b"-----BEGIN ").unwrap();
        pem.write(tag.as_bytes()).unwrap();
        pem.write(b" PRIVATE KEY-----\n").unwrap();
        pem.write(payload.as_bytes()).unwrap();
        pem.write(b"\n").unwrap();
        pem.write(b"-----END ").unwrap();
        pem.write(tag.as_bytes()).unwrap();
        pem.write(b" PRIVATE KEY-----\n").unwrap();
        let file_info = tealeaves::scan(&fs, &"/tmp/pem").unwrap();
        assert!(file_info.error.is_some());

    }
}
