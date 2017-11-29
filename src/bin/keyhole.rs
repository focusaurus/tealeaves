extern crate base64;
extern crate yasna;
use std::env;
use std::fs;
use std::io;
use std::io::{BufRead,Read};

fn to_u32(bytes: &[u8]) -> u32 {
    let mut size = 0u32;
    for (index, &byte) in bytes.iter().enumerate() {
        size = size + byte as u32;
        if index < bytes.len() -1 {size = size << 8;}
    }
    size
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
        // println!("{}", base64);
        let bytes = base64::decode(&base64).unwrap();
        let prefix = b"openssh-key-v1";
        let starts_with_prefix = bytes.len() >= prefix.len() && prefix == &bytes[0..prefix.len()];
        if  !starts_with_prefix {
            return Ok(());
        }
        println!("✓openssh-key-v1");
        // Make a reader for everything after the prefix
        let reader = io::BufReader::new(&bytes[prefix.len()..]);
        // let reader = io::BufReader::new(&bytes[prefix.len()..]).bytes();
        // // let mut string_len = [0u8;4];
        // let string_len: Vec<u8> = reader.take(4).map(|b|b.unwrap()).collect();
        // let cipher_name: Vec<u8> = reader.take(cipher_name_len as usize).map(|b|b.unwrap()).collect();

        // reader.read_exact(&mut string_len);
        let payload = &bytes[prefix.len()..];
        let cipher_name_len = to_u32(&payload[0..5]);
        let mut index = 0;
        index = index + 5;
        println!("cipher_name_len {}", cipher_name_len);
        let cipher_name = String::from_utf8_lossy(&payload[index..(index + cipher_name_len as usize)]);
        println!("cipher_name {}", cipher_name);
        // let mut cipher_name = [
        // index = index + cipher_name_len;

        // let asn = yasna::parse_ber_general(&payload, yasna::BERMode::Der, |reader| {
        //     reader.read_sequence(|reader| {
        //                              let cipher_name = try!(reader.next().read_string());
        //                              // let b = try!(reader.next().read_bool());
        //                              return Ok(cipher_name);
        //                          })
        // });
        // // let mut fields = payload.split(|&byte| byte == 0);//.filter(|byte|byte.len() > 0);
        // let cipher_name = fields.next().unwrap();
        // println!("cipher: {}", String::from_utf8_lossy(cipher_name));
/*
	byte[]	AUTH_MAGIC
	string	ciphername
	string	kdfname
	string	kdfoptions
	int	number of keys N
	string	publickey1
	string	publickey2
*/

        for (index, word) in bytes.split(|&byte| byte == 0).filter(|byte|byte.len() > 0).enumerate() {
            println!("{}: {} (len: {})", index, String::from_utf8_lossy(word), word.len());
        }
        // println!("{:?}", bytes[23] == 0);
        // println!("{}", String::from_utf8_lossy(&bytes[0..15]));
        // let asn = yasna::parse_ber_general(&bytes, yasna::BERMode::Der, |reader| {
        //     reader.read_sequence(|reader| {
        //                              Ok(())
        //                              // let i = try!(reader.next().read_i64());
        //                              // let b = try!(reader.next().read_bool());
        //                              // return Ok((i, b));
        //                          })
        // });
        // match asn {
        //     Ok(_) => println!("OK"),
        //     Err(error) => println!("Err {}", error),
        // }

    }
    Ok(())
}

fn main() {
    keyhole().unwrap();
}
