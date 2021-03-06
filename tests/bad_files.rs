extern crate base64;
extern crate rsfs;
extern crate tealeaves;
use rsfs::GenFS;
use rsfs::mem::unix::FS;
use rsfs::mem::unix::Permissions;
use rsfs::unix_ext::PermissionsExt;
use std::io::Write;
use tealeaves::leaf::Leaf;

fn memfs() -> FS {
    let fs = rsfs::mem::unix::FS::new();
    fs.create_dir_all("/tmp").unwrap();
    fs
}

#[test]
fn empty_file_gets_error() {
    let fs = memfs();
    let _empty = fs.create_file("/tmp/empty");
    let leaf = tealeaves::scan(&fs, &"/tmp/empty").unwrap();
    match leaf {
        Leaf::EmptyFile(_) => (),
        _ => panic!("expected EmptyFile"),
    }
}

#[test]
fn unreadable_file_gets_error() {
    let fs = memfs();
    let mut unreadable = fs.create_file("/tmp/unreadable").unwrap();
    unreadable.write_all(&[1, 2, 3, 4]).unwrap();
    for &mode in &[0o000, 0o002, 0o020, 0o200, 0o222] {
        fs.set_permissions("/tmp/unreadable", Permissions::from_mode(mode))
            .unwrap();
        let leaf = tealeaves::scan(&fs, &"/tmp/unreadable").unwrap();
        match leaf {
            Leaf::UnreadableFile(_) => (),
            _ => panic!("Expected Unreadable"),
        }
    }
}

#[test]
fn readable_file_gets_no_error() {
    let fs = memfs();
    let mut readable = fs.create_file("/tmp/readable").unwrap();
    readable.write_all(&[1, 2, 3, 4]).unwrap();
    for &mode in &[0o004, 0o004, 0o040, 0o400, 0o444] {
        fs.set_permissions("/tmp/readable", Permissions::from_mode(mode))
            .unwrap();
        let leaf = tealeaves::scan(&fs, &"/tmp/readable").unwrap();
        match leaf {
            Leaf::SmallFile(_) => (),
            _ => panic!("Expected SmallFile"),
        }
    }
}

#[test]
fn low_size_gets_error() {
    let fs = memfs();
    let mut small = fs.create_file("/tmp/small").unwrap();
    small.write_all(&[1, 2, 3, 4]).unwrap();
    let leaf = tealeaves::scan(&fs, &"/tmp/small").unwrap();
    match leaf {
        Leaf::SmallFile(_) => (),
        _ => panic!("Expected SmallFile"),
    }
}

#[test]
fn prefix_then_bogus_gets_error() {
    let fs = memfs();
    let mut file = fs.create_file("/tmp/prefix_then_bogus").unwrap();
    file.write_all(b"ssh-rsa is a cool kind of file 1111111111 2222222222")
        .unwrap();
    let leaf = tealeaves::scan(&fs, &"/tmp/prefix_then_bogus").unwrap();
    match leaf {
        Leaf::Error(_, _) => (),
        _ => panic!("Expected Error"),
    }
}

#[test]
fn not_pem_gets_detected() {
    let fs = memfs();
    let mut not_pem = fs.create_file("/tmp/not_pem").unwrap();
    not_pem
        .write_all(b"Hi this is not even a PEM file or anything, but it's long enough to maybe")
        .unwrap();
    let leaf = tealeaves::scan(&fs, &"/tmp/not_pem").unwrap();
    match leaf {
        Leaf::MediumFile(_) => (),
        _ => panic!("Expected MediumFile"),
    }
}

#[test]
fn pem_gets_detected() {
    let fs = memfs();
    let mut pem = fs.create_file("/tmp/pem").unwrap();
    pem.write_all(
        b"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACA2WS+xYVACuTmyxQDByFfD5tRfZFnxq03l04+tYPxExgAAAKj+L4az/i+G
swAAAAtzc2gtZWQyNTUxOQAAACA2WS+xYVACuTmyxQDByFfD5tRfZFnxq03l04+tYPxExg
AAAEBIhgNOlzPnH3cAul5S0VSrnirdVr6TVDL2gVDXIEu6FTZZL7FhUAK5ObLFAMHIV8Pm
1F9kWfGrTeXTj61g/ETGAAAAH1RlYWxldmVzIHRlc3QgRUQyNTUxOSBTU0ggS2V5IDEBAg
MEBQY=
-----END OPENSSH PRIVATE KEY-----
",
    ).unwrap();
    let leaf = tealeaves::scan(&fs, &"/tmp/pem").unwrap();
    match leaf {
        Leaf::SshKey(_, _) => (),
        _ => panic!("Expected SshKey"),
    }
}

#[test]
fn high_size_gets_error() {
    let fs = memfs();
    let mut big = fs.create_file("/tmp/big").unwrap();
    for _x in 0..1024 {
        big.write_all(&[1, 2, 3, 4, 5, 6, 7]).unwrap();
    }
    let leaf = tealeaves::scan(&fs, &"/tmp/big").unwrap();
    match leaf {
        Leaf::LargeFile(_) => (),
        _ => panic!("Expected LargeFile"),
    }
}

#[test]
fn pem_long_field_gets_detected() {
    let fs = memfs();
    let mut pem = fs.create_file("/tmp/pem-too-long-field").unwrap();
    let valid_prefix = b"openssh-key-v1\0";
    // field length is above 4096 safe limit we will read
    // 4097 length:  00 00 10 01 in hex
    let bogus_length = &[0, 0, 0b0000_0010, 1][..];
    let base64 = base64::encode(&[valid_prefix, bogus_length].concat());
    pem.write_all(b"-----BEGIN OPENSSH PRIVATE KEY-----\n")
        .unwrap();
    pem.write_all(base64.as_bytes()).unwrap();
    pem.write_all(b"\n").unwrap();
    pem.write_all(b"-----END OPENSSH PRIVATE KEY-----\n")
        .unwrap();
    let result = tealeaves::scan(&fs, &"/tmp/pem-too-long-field");
    assert!(result.is_err());
}

#[test]
fn asn1_error_gets_detected() {
    let fs = memfs();
    let mut pem = fs.create_file("/tmp/pem").unwrap();
    let mut payload = vec![0];
    payload.extend_from_slice(b"ssh-rsa\0"); // magic prefix
    payload.extend_from_slice(b"this-is-not-asn1");
    let tags = ["RSA", "DSA", "EC"];
    for tag in &tags {
        let payload = base64::encode(&payload);
        pem.write_all(b"-----BEGIN ").unwrap();
        pem.write_all(tag.as_bytes()).unwrap();
        pem.write_all(b" PRIVATE KEY-----\n").unwrap();
        pem.write_all(payload.as_bytes()).unwrap();
        pem.write_all(b"\n").unwrap();
        pem.write_all(b"-----END ").unwrap();
        pem.write_all(tag.as_bytes()).unwrap();
        pem.write_all(b" PRIVATE KEY-----\n").unwrap();
        let result = tealeaves::scan(&fs, &"/tmp/pem");
        assert!(result.is_err());
    }
}
