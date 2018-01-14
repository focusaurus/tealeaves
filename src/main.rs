#[macro_use(crate_version)]
extern crate clap;
extern crate rsfs;
extern crate tealeaves;
use clap::{App, Arg};
use std::{env, fs, io, process};
use std::path::PathBuf;
use tealeaves::file_info::FileInfo;

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

    // Gather the list of paths we will inspect
    // either command line args or by listing ~/.ssh
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

    // Scan all the paths
    let results: Vec<Result<tealeaves::FileInfo, String>> =
        paths.iter().map(|p| tealeaves::scan(&fs, &p)).collect();

    // Split the results apart into Err and Ok
    let (errors, oks): (Vec<Result<FileInfo, String>>, Vec<Result<FileInfo, String>>) =
        results.into_iter().partition(|r| r.is_err());

    // Print the errors
    for result_error in errors {
        match result_error {
            Err(message) => eprintln!("{}", message),
            _ => (),
        };
    }

    // Unwrap all the Oks so we don't need to deal with Result any more
    let infos: Vec<FileInfo> = oks.into_iter().map(|r| r.unwrap()).collect();

    // Split into public keys and all other variants
    // so we can match public/private pairs together
    let (publics, others): (Vec<FileInfo>, Vec<FileInfo>) =
        infos.into_iter().partition(|i| match i {
            &FileInfo::SshKey(ref _pb, ref key) => key.is_public,
            _ => false,
        });

    // Print out everything except public keys
    for info in others {
        match info {
            FileInfo::SshKey(ref _pb, ref key) => {
                print!("{}", info);
                if !key.is_public {
                    let pair = publics.iter().find(|pub_info| match *pub_info {
                        &FileInfo::SshKey(ref _pb, ref pub_key) => pub_key.is_pair(&key),
                        _ => false,
                    });
                    match pair {
                        Some(pub_key) => match *pub_key {
                            FileInfo::SshKey(ref path, _) => {
                                println!("\tpairs with public key at: {}\n", path.display());
                            }
                            _ => println!("\n"),
                        },
                        _ => println!(""),
                    }
                }
            }
            _ => println!("{}", info),
        }
    }

    // print out the public keys
    for public_key in publics {
        println!("{}", public_key);
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
