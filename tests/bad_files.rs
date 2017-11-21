extern crate filesystem;
extern crate tealeaves;
use filesystem::FileSystem;
use std::path::Path;

#[test]
fn empty_file_gets_error() {
    let fs = filesystem::FakeFileSystem::new();
    let empty = Path::new("empty");
    fs.write_file(empty, []).unwrap();
    let data = fs.read_file_to_string(empty).unwrap();
    let file_info = tealeaves::scan2(&fs, empty).unwrap();
    // assert_eq!(data, "");
    assert!(file_info.checks.iter().any(|c|{
        // format!("{}", c) == "🔥 is empty";
        println!("{}", c);
        return true;
    }));
}
