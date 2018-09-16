use nom_pem;
use std::fmt;
use time;
use x509_parser;

#[derive(Debug)]
pub struct Certificate {
    pub expires: time::Tm,
    pub subject: String,
    // Using der_parser::oid::Oid for this causes cargo conflicts
    pub algorithm: String,
}

impl Certificate {
    pub fn new(subject: String, expires: time::Tm, algorithm: String) -> Self {
        Self {
            expires,
            subject,
            algorithm,
        }
    }

    pub fn is_expired(&self) -> bool {
        time::now_utc() > self.expires
    }

    fn format_expiration(&self) -> String {
        time::strftime("%Y-%m-%d", &self.expires).unwrap_or_else(|_| "?".into())
    }
}

impl fmt::Display for Certificate {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        let host = self.subject.rsplit('=').nth(0).unwrap_or("?");
        output.push_str(&format!("x509 TLS Certificate (host {})", host));
        if self.is_expired() {
            output.push_str("\n\t🚨 expired ");
        } else {
            output.push_str("\n\t✓ expires ");
        }
        output.push_str(&self.format_expiration().to_string());
        // http://www.alvestrand.no/objectid/1.2.840.113549.1.1.5.html
        if self.algorithm == "1.2.840.113549.1.1.5" {
            output.push_str("\n\t🚨 insecure SHA1 signature algorithm");
        }
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
    let (_x, xcert) = x509_parser::x509_parser(&block.data).map_err(|nie| format!("{:?}", nie))?;
    let tbs = xcert.tbs_certificate;
    Ok(Certificate::new(
        tbs.subject.to_string(),
        tbs.validity.not_after,
        xcert.signature_algorithm.algorithm.to_string(),
    ))
}
