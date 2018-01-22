use std::fmt;
use time;

#[derive(Debug)]
pub struct Certificate {
    pub subject: String,
    pub validity: Vec<time::Tm>,
}

impl Certificate {
    pub fn new() -> Self {
        Self {
            subject: "".into(),
            validity: vec![],
        }
    }

    pub fn is_expired(&self) -> bool {
        if self.validity.len() < 2 {
            return true;
        }
        time::now_utc() > self.validity[1]
    }

    fn format_expiration(&self) -> String {
        if self.validity.len() < 2 {
            return "?".into();
        }
        match time::strftime("%Y-%m-%d", &self.validity[1]) {
            Ok(date) => date,
            Err(_) => "?".into(),
        }
    }
}

impl Default for Certificate {
    fn default() -> Self {
        Self::new()
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
