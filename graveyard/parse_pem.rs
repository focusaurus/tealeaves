
#[derive(Debug)]
struct Pem {
    pub tag: String,
    pub headers: Vec<String>,
    pub body: Vec<u8>,
}

fn parse_pem(pem: &str) -> Pem {
    let pem_prefix = "-----BEGIN ";
    let pem_suffix = "-----";
    let mut pem_header = "";
    let mut headers = vec![];
    let mut body = vec![];
    let mut blank_found = false;
    for (index, line) in pem.lines().enumerate() {
        if index == 0 {
            pem_header = line;
            if line.starts_with(pem_prefix) {
                pem_header = &line[pem_prefix.len()..];
            }
            if pem_header.ends_with(pem_suffix) {
                pem_header = &pem_header[..pem_header.len() - pem_suffix.len()];
            }
            continue;
        }
        if !blank_found && line.is_empty() {
            blank_found = true;
            continue;
        }
        if !blank_found {
            headers.push(line.to_owned());
        } else {
            body.push(line.to_owned());
        }
    }
    if !blank_found {
        body = headers;
        headers = vec![];
    }
    body.pop(); // discard pem_footer
    let body = base64::decode(&body.concat()).unwrap();
    Pem {
        tag: pem_header.to_string(),
        headers,
        body,
    }
}
