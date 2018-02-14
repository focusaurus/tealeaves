use std::fmt;
use time;

#[derive(Debug)]
pub struct Certificate {
    pub subject: String,
    pub expires: time::Tm,
}

impl Certificate {
    pub fn new(subject: String, expires: time::Tm) -> Self {
        Self { subject, expires }
    }

    pub fn is_expired(&self) -> bool {
        time::now_utc() > self.expires
    }

    fn format_expiration(&self) -> String {
        match time::strftime("%Y-%m-%d", &self.expires) {
            Ok(date) => date,
            Err(_) => "?".into(),
        }
    }
}
//
// impl Default for Certificate {
//     fn default() -> Self {
//         Self::new()
//     }
// }

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
