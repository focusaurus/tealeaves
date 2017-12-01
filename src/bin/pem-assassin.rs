extern crate pem;
extern crate yasna;
use std::env;
use std::fs;
use std::io;
use std::io::Read;
use std::iter::Iterator;
use std::error::Error;

fn assassin() -> io::Result<()> {
    for path in env::args().skip(1) {
        println!("{}", path);
        let mut file = fs::File::open(path)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;

        let pem_result = pem::parse(content);
        match pem_result {
            Ok(pem) => {
                println!("PEM {} {}", pem.tag, pem.contents.len());
                let asn_result = yasna::parse_der(&pem.contents, |reader| {
                    reader.read_sequence(|reader| {
                                             // let i = try!(reader.next().read_i64());
                                             // let b = try!(reader.next().read_bool());
                                             // return Ok((i, b));
                                             return Ok(());
                                         })
                });
                match asn_result {
                    Ok(_) => println!("ASN.1 OK"),
                    Err(message) => println!("ASN.1 NOPE {}", message.description()),
                }

            }
            _ => println!("NOPE"),
        }
    }
    Ok(())
}

fn main() {
    match assassin() {
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(10);
        }
        _ => (),
    }
}
