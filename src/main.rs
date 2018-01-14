#[macro_use(crate_version)]
extern crate clap;
extern crate rsfs;
extern crate tealeaves;
use clap::{App, Arg};
use std::{env, fs, io, process};
use std::path::PathBuf;
use tealeaves::file_info::{Algorithm, FileInfo, FileType};

fn tealeaves2() -> io::Result<()> {
    let mut results: Vec<Result<FileInfo, String>> = vec![];
    let mut f1: FileInfo = Default::default();
    let mut f2: FileInfo = Default::default();
    f1.file_type = FileType::PublicSshKey;
    f2.file_type = FileType::PrivateSshKey;
    results.push(Ok(f1));
    results.push(Ok(f2));
    results.push(Err("oops".to_owned()));
    let (errors, oks): (Vec<Result<FileInfo, String>>, Vec<Result<FileInfo, String>>) =
        results.into_iter().partition(|r| r.is_err());
    println!("errors {}", errors.len());
    let infos: Vec<FileInfo> = oks.into_iter().map(|r| r.unwrap()).collect();
    println!("infos {}", infos.len());
    let (publics, others): (Vec<FileInfo>, Vec<FileInfo>) =
        infos.into_iter().partition(|f| match f.file_type {
            FileType::PublicSshKey => true,
            _ => false,
        });
    println!("publics {}", publics.len());
    Ok(())
}

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

    // What do I actually want to do here?
    // First, I want all the private RSA keys

    let results: Vec<Result<tealeaves::FileInfo, String>> =
        paths.iter().map(|p| tealeaves::scan(&fs, &p)).collect();
    let (errors, oks): (Vec<Result<FileInfo, String>>, Vec<Result<FileInfo, String>>) =
        results.into_iter().partition(|r| r.is_err());
    for result_error in errors {
        match result_error {
            Err(message) => eprintln!("{}", message),
            _ => (),
        };
    }
    let infos: Vec<FileInfo> = oks.into_iter().map(|r| r.unwrap()).collect();
    let (publics, others): (Vec<FileInfo>, Vec<FileInfo>) =
        infos.into_iter().partition(|f| match f.file_type {
            FileType::PublicSshKey => true,
            _ => false,
        });
    for info in others {
        match info.file_type {
            FileType::PrivateSshKey => {
                let private_key = info.ssh_key.unwrap();
                println!("private alg {}", private_key.algorithm);
                // let matching_public_key = publics.iter().find(|f| f.ssh_key.unwrap().is_pair(&private_key));
                // if let Some(mpk) = matching_public_key {
                //     println!("match {}", mpk);
                // }
            }
            _ => println!("{}", info),
        }
    }

    // let (infos, errors): (Vec<Result<tealeaves::FileInfo, String>>, Vec<Result<tealeaves::FileInfo, String>>) = results.iter().partition(|ref r|r.is_err());
    // let public_keys: Vec<&Result<tealeaves::FileInfo, String>> = oks.into_iter().filter(|r| match *r {
    //     &Ok(ref f) => match f.file_type {
    //         FileType::PublicSshKey => true,
    //         _ => false
    //     },
    //     _ => false,
    // }).collect();
    // println!("public_keys {}", public_keys.len());
    // .map(||
    // let private_keys = keys.map(|r| r.unwrap().ssh_key.unwrap()).filter(|k|!k.is_public);
    // r.is_ok() && r.unwrap().ssh_key.is_some() && !r.unwrap().ssh_key.unwrap().is_public
    // }) {
    // .filter(|r|r.unwrap().ssh_key.is_some()).filter(|rf.ssh_key.unwrap()).filter(|s|!s.is_public) {
    // }
    // let private_keys = results.filter(|r|
    // let mut privates = vec![];
    // let mut publics = vec![];
    // for result in results {
    //     match result {
    //         Ok(info) => {
    //             println!("{}", info);
    //             match info.ssh_key {
    //                 Some(ref key) => {
    //                     if key.is_public {
    //                         publics.push(&info);
    //                     } else {
    //                         privates.push(&info);
    //                     }
    //                 },
    //                 None => ()
    //             }
    //             // if info.ssh_key.is_some() && !info.ssh_key.unwrap().is_public {
    //             //     println!("PRIVATE {}", info.ssh_key.unwrap());
    //             // }
    //         }
    //         Err(message) => eprintln!("{}", message),
    //     };
    // }
    // for private_info in privates {
    //     match (*private_info).ssh_key.unwrap().algorithm {
    //         Algorithm::Rsa(private_modulus) => {
    //             for public_info in publics {
    //                 match public_info.ssh_key.unwrap().algorithm {
    //                     Algorithm::Rsa(public_modulus) => {
    //                         if private_modulus == public_modulus {
    //                             println!("match {} {}", private_info.path_buf.display(), public_info.path_buf.display());
    //                         }
    //                     },
    //                     _ => ()
    //                 }
    //             }
    //             println!("RSA");
    //         }
    //         _ => {}
    //     }
    // }
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
