#[macro_use(crate_version)]
extern crate clap;
extern crate rsfs;
extern crate tealeaves;
use clap::{App, Arg};
use std::{env, fs, io, process};
use std::path::PathBuf;

fn tealeaves() -> io::Result<()> {
    let matches = App::new("tealeaves")
        .version(crate_version!())
        .about("Helps you figure out TLS/SSH stuff")
        .arg(
            Arg::with_name("paths")
                .takes_value(true)
                .multiple(true)
                .help("Paths to files/directories of interest"),
        )
        .get_matches();
    let fs = rsfs::disk::FS;
    let mut paths: Vec<PathBuf> = vec![];
    // Sigh. PathBuf does not impl FromStr
    // https://github.com/rust-lang/rust/issues/44431
    match matches.values_of("paths") {
        Some(values) => {
            paths = values.map(|v| PathBuf::from(v)).collect();
        }
        None => {
            // If no paths on command line, scan ~/.ssh
            match env::home_dir() {
                Some(home) => {
                    let dot_ssh = home.join(".ssh");
                    paths = fs::read_dir(dot_ssh)?
                        .map(|dir_entry| dir_entry.unwrap().path())
                        .collect();
                }
                None => eprintln!("Error determining your home directory via HOME env var"),
            }
        }
    }

    let results: Vec<Result<tealeaves::FileInfo, String>> =
        paths.iter().map(|p| tealeaves::scan(&fs, &p)).collect();
    for result in results {
        match result {
            Ok(info) => println!("{}", info),
            Err(message) => eprintln!("{}", message),
        };
    }
    Ok(())
}

fn main() {
    match tealeaves() {
        Ok(_) => {}
        Err(error) => {
            eprintln!("{}", error);
            process::exit(10);
        }
    }
}
