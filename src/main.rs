#[macro_use]
extern crate clap;
extern crate tealeaves;
use clap::{Arg, App};
use std::path::{Path, PathBuf};

fn main() {
    let matches = App::new("tealeaves")
            .version(crate_version!())
            .about("Helps you figure out TLS/SSH stuff")
            .arg(Arg::with_name("paths")
                .takes_value(true)
                 .multiple(true)
                 .help("Paths to files/directories of interest"))
            // .arg(Arg::with_name("count")
            //          .short("c")
            //          .long("count")
            //          .takes_value(true)
            //          .help("How many words to generate"))
            .get_matches();
    // let path = Path::new(".");
    //
    // for m in matches.values_of("paths").unwrap().collect::<Vec<&str>>() {
    //     println!("match {:?}", m);
    // }
    for info in matches
            .values_of("paths")
            .unwrap()
            .map(|p| tealeaves::scan(&Path::new(&p))) {
        println!("{:?}", info);
    }
    // for info in tealeaves::scan(path).iter() {
    // }
}
