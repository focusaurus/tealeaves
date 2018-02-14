use nom_pem;
use std::fmt;
use time;
use x509_parser;

#[derive(Debug)]
pub struct Certificate {
    pub expires: time::Tm,
    pub subject: String,
}

impl Certificate {
    pub fn new(subject: String, expires: time::Tm) -> Self {
        Self { expires, subject }
    }

    pub fn is_expired(&self) -> bool {
        time::now_utc() > self.expires
    }

    fn format_expiration(&self) -> String {
        time::strftime("%Y-%m-%d", &self.expires).unwrap_or("?".into())
    }
}

impl fmt::Display for Certificate {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        let host = self.subject.rsplit("=").nth(0).unwrap_or("?");
        output.push_str(&format!("x509 TLS Certificate (host {})", host));
        if self.is_expired() {
            output.push_str(&format!("\n\t🚨 expired "));
        } else {
            output.push_str(&format!("\n\t✓ expires "));
        }
        output.push_str(&format!("{}", self.format_expiration()));
        write!(out, "{}", output)
    }
}

fn strerr<T>(error: T) -> String
where
    T: fmt::Debug,
{
    return format!("{:?}", error);
}

pub fn parse(bytes: &[u8]) -> Result<Certificate, String> {
    let block: nom_pem::Block = nom_pem::decode_block(bytes).map_err(strerr)?;
    let xcert = x509_parser::x509_parser(&block.data)
        .to_full_result()
        .map_err(|nie| format!("{:?}", nie))?;
    let tbs = xcert.tbs_certificate().map_err(|nie| format!("{:?}", nie))?;
    let tm_vec = xcert
        .tbs_certificate()
        .and_then(|tbs| tbs.validity())
        .map_err(strerr)?;
    let expires: Result<time::Tm, String> =
        tm_vec.into_iter().nth(1).ok_or("Validity Error".into());
    return Ok(Certificate::new(tbs.subject().to_string(), expires?));
}
