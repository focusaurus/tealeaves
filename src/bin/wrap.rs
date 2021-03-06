use std::io;
use std::io::Read;
use std::iter::Iterator;

fn wrap() -> io::Result<()> {
    let mut file = std::io::stdin();
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    let content: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    for (index, character) in content.chars().enumerate() {
        print!("{}", character);
        if (index + 1) % 64 == 0 {
            println!();
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = wrap() {
        eprintln!("{}", error);
        std::process::exit(10);
    }
}
