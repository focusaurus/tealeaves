extern crate rsfs;
extern crate structopt;
#[macro_use(StructOpt)]
extern crate structopt_derive;
extern crate tealeaves;
use std::{env, fs, io};
use std::path::PathBuf;
use structopt::StructOpt;
use tealeaves::leaf::Leaf;

#[derive(StructOpt, Debug)]
#[structopt(name = "tealeaves", about = "Helps you figure out SSH/TLS stuff")]
struct Opt {
    #[structopt(help = "Paths to files/directories of interest", parse(from_os_str))]
    paths: Vec<PathBuf>,
}

type LeafResults = Vec<Result<Leaf, String>>;

fn tealeaves() -> io::Result<()> {
    let opt = Opt::from_args();
    let fs = rsfs::disk::FS;

    // Gather the list of paths we will inspect
    // either command line args or by listing ~/.ssh
    let mut paths: Vec<PathBuf> = opt.paths;
    if paths.len() < 1 {
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
    // Scan all the paths
    let results: Vec<Result<tealeaves::Leaf, String>> =
        paths.iter().map(|p| tealeaves::scan(&fs, &p)).collect();

    // Split the results apart into Err and Ok
    let (errors, oks): (LeafResults, LeafResults) = results.into_iter().partition(|r| r.is_err());

    // Print the errors
    for result_error in errors {
        if let Err(message) = result_error {
            eprintln!("{}", message);
        }
    }

    // Unwrap all the Oks so we don't need to deal with Result any more
    let leaves: Vec<Leaf> = oks.into_iter().map(|r| r.unwrap()).collect();

    // Split into public keys and all other variants
    // so we can match public/private pairs together
    let (publics, others): (Vec<Leaf>, Vec<Leaf>) = leaves.into_iter().partition(|i| match *i {
        Leaf::SshKey(ref _pb, ref key) => key.is_public,
        _ => false,
    });

    // Print out everything except public keys
    for leaf in others {
        match leaf {
            Leaf::SshKey(ref _pb, ref key) => {
                print!("{}", leaf);
                if !key.is_public {
                    let pair = publics.iter().find(|pub_leaf| match *(*pub_leaf) {
                        Leaf::SshKey(ref _pb, ref pub_key) => pub_key.is_pair(key),
                        _ => false,
                    });
                    match pair {
                        Some(pub_key) => match *pub_key {
                            Leaf::SshKey(ref path, _) => {
                                println!("\tpairs with public key at: {}\n", path.display());
                            }
                            _ => println!("\n"),
                        },
                        _ => println!(),
                    }
                }
            }
            _ => println!("{}", leaf),
        }
    }

    // print out the public keys
    for public_key in publics {
        println!("{}", public_key);
    }

    Ok(())
}

fn main() {
    if let Err(error) = tealeaves() {
        eprintln!("{}", error);
        std::process::exit(10);
    }
}
