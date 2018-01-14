#[macro_use(crate_version)]
extern crate clap;
extern crate rsfs;
extern crate tealeaves;
use clap::{App, Arg};
use std::{env, fs, io, process};
use std::path::PathBuf;
use tealeaves::file_info::FileInfo3;

fn tealeaves3() -> io::Result<()> {
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

    let results: Vec<Result<tealeaves::FileInfo3, String>> =
        paths.iter().map(|p| tealeaves::scan(&fs, &p)).collect();
    let (errors, oks): (
        Vec<Result<FileInfo3, String>>,
        Vec<Result<FileInfo3, String>>,
    ) = results.into_iter().partition(|r| r.is_err());
    for result_error in errors {
        match result_error {
            Err(message) => eprintln!("{}", message),
            _ => (),
        };
    }
    let infos: Vec<FileInfo3> = oks.into_iter().map(|r| r.unwrap()).collect();
    let (publics, others): (Vec<FileInfo3>, Vec<FileInfo3>) =
        infos.into_iter().partition(|i| match i {
            &FileInfo3::SshKey(ref _pb, ref key) => key.is_public,
            _ => false,
        });
    // let publics: Vec<&FileInfo3> = infos
    //     .iter()
    //     .filter(|fi| match *fi {
    //         &FileInfo3::SshKey(ref key) => key.is_public,
    //         _ => false,
    //     })
    //     .collect();
    // println!("publics {}", publics.len());
    for info in others {
        match info {
            FileInfo3::SshKey(ref _pb, ref key) => {
                if !key.is_public {
                    let pair = publics.iter().find(|pub_info| match *pub_info {
                        &FileInfo3::SshKey(ref _pb, ref pub_key) => pub_key.is_pair(&key),
                        _ => false,
                    });
                    match pair {
                        Some(pub_key) => println!("pair {}", pub_key),
                        _ => (),
                    }
                    println!("{}", info);
                }
            }
            _ => println!("{}", info),
        }
    }

    Ok(())
}

fn main() {
    match tealeaves3() {
        Ok(_) => {}
        Err(error) => {
            eprintln!("{}", error);
            process::exit(10);
        }
    }
}
