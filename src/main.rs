#[macro_use]
extern crate clap;
extern crate rsfs;
extern crate tealeaves;
use clap::{App, Arg};
use std::{env, fs, io, process};

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
    let paths = matches.values_of("paths");
    match paths {
        Some(paths) => for result in paths.map(|p| tealeaves::scan(&fs, &p)) {
            match result {
                Ok(info) => println!("{}", info),
                Err(message) => eprintln!("{}", message),
            };
        },
        None => {
            // If no paths on command line, scan ~/.ssh
            match env::home_dir() {
                Some(home) => {
                    let dot_ssh = home.join(".ssh");
                    for result in fs::read_dir(dot_ssh)?
                        .map(|r| r.unwrap())
                        .map(|dir_entry| tealeaves::scan(&fs, &dir_entry.path()))
                    {
                        match result {
                            Ok(info) => println!("{}", info),
                            Err(message) => eprintln!("{}", message),
                        };
                    }
                }
                None => eprintln!("Error determining your home directory via HOME env var"),
            }
        }
    };
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
