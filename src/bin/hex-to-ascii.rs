extern crate hex;
use std::io;
use std::io::{ErrorKind, Read};
use std::iter::Iterator;
use hex::decode;
use std::error::Error;

fn wrap() -> io::Result<()> {
    let mut file = std::io::stdin();
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let content: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    match decode(content) {
        Ok(bin) => {
            println!("{}", String::from_utf8_lossy(&bin));
            Ok(())
        }
        Err(err) => Err(io::Error::new(ErrorKind::InvalidData, err.description())),
    }
}

fn main() {
    if let Err(error) = wrap() {
        eprintln!("{}", error);
        std::process::exit(10);
    }
}
