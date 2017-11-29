#[macro_use]
extern crate clap;
extern crate rsfs;
extern crate tealeaves;
use clap::{Arg, App};

fn main() {
    let matches = App::new("tealeaves")
        .version(crate_version!())
        .about("Helps you figure out TLS/SSH stuff")
        .arg(Arg::with_name("paths")
                 .takes_value(true)
                 .multiple(true)
                 .help("Paths to files/directories of interest"))
        .get_matches();
    let fs = rsfs::disk::FS;
    for info in matches
            .values_of("paths")
            .unwrap()
            .map(|p| tealeaves::scan4(&fs, &p)) {
        println!("{}", info.unwrap());
    }
}
