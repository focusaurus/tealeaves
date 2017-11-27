extern crate rsfs;
extern crate tealeaves;
use rsfs::GenFS;
use rsfs::unix_ext::PermissionsExt;
use rsfs::Permissions;
use rsfs::Metadata;
use rsfs::unix_ext::FileExt;
use rsfs::mem::unix::FS;

// fn memfs2<P: Permissions + PermissionsExt,
//           M: Metadata<Permissions = P>,
//           F: GenFS<Permissions = P, Metadata = M>>
//     ()
//     -> F
// {
//     let fs = rsfs::mem::unix::FS::new();
//     fs.create_dir_all("/tmp").unwrap();
//     fs
// }

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
    // let fs = rsfs::mem::unix::FS::new();
    // fs.create_dir_all("/tmp").unwrap();
    let fs = memfs1();
    let unreadable = fs.create_file("/tmp/unreadable").unwrap();
    fs.metadata("/tmp/unreadable")
        .unwrap()
        .permissions()
        .set_mode(0o000);
    let file_info = tealeaves::scan(&fs, &"/tmp/unreadable").unwrap();
    assert!(file_info
                .checks
                .iter()
                .any(|c| format!("{}", c) == "🔥 is empty"));
}
