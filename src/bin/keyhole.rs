extern crate base64;
extern crate byteorder;
use byteorder::{BigEndian, ReadBytesExt};
use std::env;
use std::fs;
use std::io;
use std::io::{BufRead, Read};
use std::iter::Iterator;

fn read_string<R: ReadBytesExt + Read>(reader: &mut R) -> String {
    let len = reader.read_u32::<BigEndian>().unwrap();
    let mut word = vec![0u8;len as usize];
    reader.read_exact(&mut word.as_mut_slice()).unwrap();
    String::from_utf8(word).unwrap()
}

fn keyhole() -> io::Result<()> {
    for path in env::args().skip(1) {
        println!("{}", path);
        let file = fs::File::open(path)?;
        let reader = io::BufReader::new(&file);
        let base64: String = reader
            .lines()
            .map(|l| l.unwrap())
            .filter(|line| !line.starts_with("-"))
            .collect();
        let bytes = base64::decode(&base64).unwrap();
        let prefix = b"openssh-key-v1";
        let starts_with_prefix = bytes.len() >= prefix.len() && prefix == &bytes[0..prefix.len()];
        if !starts_with_prefix {
            return Ok(());
        }
        println!("✓openssh-key-v1");

        /*
        byte[]	AUTH_MAGIC
        string	ciphername
        string	kdfname
        string	kdfoptions
        int	number of keys N
        string	publickey1
        string	publickey2
*/

        // Make a reader for everything after the prefix plus the null byte
        let mut reader = io::BufReader::new(&bytes[prefix.len() + 1..]);
        let cipher_name = read_string(&mut reader);
        println!("cipher: {}", cipher_name);
        let kdfname = read_string(&mut reader);
        println!("kdfname: {}", kdfname);
        let kdfoptions = read_string(&mut reader);
        println!("kdfoptions: {}", kdfoptions);
        let pub_key_count = reader.read_u32::<BigEndian>().unwrap();
        println!("key count {}", pub_key_count);

    }
    Ok(())
}

fn main() {
    keyhole().unwrap();
}
