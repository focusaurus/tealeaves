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
    let xcert = x509_parser::x509_parser(&block.data)
        .to_full_result()
        .map_err(|nie| format!("{:?}", nie))?;
    let tbs = xcert.tbs_certificate().map_err(strerr)?;
    let tm_vec = xcert
        .tbs_certificate()
        .and_then(|tbs| tbs.validity())
        .map_err(strerr)?;
    let expires: Result<time::Tm, String> =
        tm_vec.into_iter().nth(1).ok_or("Validity Error".into());
    let algorithm = xcert.signature_algorithm().map_err(strerr);
    return Ok(Certificate::new(
        tbs.subject().to_string(),
        expires?,
        algorithm?.algorithm.to_string(),
    ));
}
