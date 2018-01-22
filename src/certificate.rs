use std::fmt;

#[derive(Debug)]
pub struct Certificate {
    pub subject: String,
}

impl Certificate {
    pub fn new() -> Self {
        Self { subject: "".into() }
    }
}

impl Default for Certificate {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for Certificate {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        write!(
            out,
            "x509 TLS Certificate
\tSubject: {}
",
            self.subject
        )
    }
}
