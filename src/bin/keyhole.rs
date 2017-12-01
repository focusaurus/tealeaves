extern crate base64;
extern crate byteorder;
use byteorder::{BigEndian, ReadBytesExt};
use std::env;
use std::fs;
use std::io;
use std::io::{BufRead, Read};
use std::iter::Iterator;

/// Read a length-prefixed field in the format openssh uses
/// which is a 4-byte big-endian u32 length
/// followed by that many bytes of payload
fn read_field<R: ReadBytesExt + Read>(reader: &mut R) -> Vec<u8> {
    let len = reader.read_u32::<BigEndian>().unwrap();
    let mut word = vec![0u8;len as usize];
    reader.read_exact(&mut word.as_mut_slice()).unwrap();
    word
}

fn identify_pem(path: &str) -> io::Result<String> {
    let mut result = String::from(path);
    result.push_str(path);
    result.push_str("\n");
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(&file);
    let base64: String = reader
        .lines()
        .map(|l| l.unwrap())
        .filter(|line| !line.starts_with("-"))
        .collect();
    let base64_result = base64::decode(&base64);
    if base64_result.is_err() {
        return Err(io::Error::new(io::ErrorKind::Other, "Invalid base64 encoding".to_string()));
    }
    let bytes = base64_result.unwrap();

    /*
    byte[]	AUTH_MAGIC
    string	ciphername
    string	kdfname
    string	kdfoptions
    int	number of keys N
    string	publickey1
    string	publickey2
    */
    let prefix = b"openssh-key-v1";
    let starts_with_prefix = bytes.len() >= prefix.len() && prefix == &bytes[0..prefix.len()];
    if !starts_with_prefix {
        return Err(io::Error::new(io::ErrorKind::Other, "Unknown key format".to_string()));
    }
    result.push_str("\t✓ OpenSSH private key (v1)");

    // Make a reader for everything after the prefix plus the null byte
    let mut reader = io::BufReader::new(&bytes[prefix.len() + 1..]);
    let cipher_name = read_field(&mut reader);
    match cipher_name.as_slice() {
        b"none" => result.push_str(", not encrypted"),
        _ => {
            result.push_str(", encrypted with ");
            result.push_str(&String::from_utf8_lossy(&cipher_name));
        }
    }
    let kdfname = read_field(&mut reader);
    // kdfoptions (don't really care)
    let kdfoptions = read_field(&mut reader);
    let pub_key_count = reader.read_u32::<BigEndian>().unwrap();
    let key_length = reader.read_u32::<BigEndian>().unwrap();
    let key_type = read_field(&mut reader);
    result.push_str(", algorithm: ");
    result.push_str(match key_type.as_slice() {
                        b"ssh-ed25519" => "ed25519",
                        b"ssh-rsa" => "RSA",
                        b"ssh-dss" => "DSA",
                        _ => "UNKNOWN",
                    });
    Ok(result)
}

fn identify(path: &str) -> io::Result<String> {
    Ok("".to_string())
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
        let cipher_name = read_field(&mut reader);
        // println!("cipher: {}",
        //        match cipher_name.as_slice() {
        //            b"none" => "none",
        //            b"aes256-cbc" => "aes256-cbc",
        //            _ => "UNKNOWN",
        //        });

        let kdfname = read_field(&mut reader);
        match cipher_name.as_slice() {
            b"none" => println!("not encrypted"),
            _ => {
                println!("encrypted with {}", String::from_utf8_lossy(&cipher_name));
            }
        }

        // kdfoptions (don't really care)
        let kdfoptions = read_field(&mut reader);
        let pub_key_count = reader.read_u32::<BigEndian>().unwrap();
        // println!("key count {}", pub_key_count);
        let key_length = reader.read_u32::<BigEndian>().unwrap();
        let key_type = read_field(&mut reader);
        // println!("{}", String::from_utf8_lossy(&key_type));
        println!("algorithm: {}",
                 match key_type.as_slice() {
                     b"ssh-ed25519" => "ed25519",
                     b"ssh-rsa" => "RSA",
                     b"ssh-dss" => "DSA",
                     _ => "UNKNOWN",
                 });
    }
    Ok(())
}

fn main() {
    match keyhole() {
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(10);
        }
        _ => (),
    }
}
