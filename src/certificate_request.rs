#[derive(Debug)]
pub struct CertificateRequest {
    pub is_encrypted: bool,
}

impl CertificateRequest {
    pub fn new() -> Self {
        Self {
            is_encrypted: false,
        }
    }
}

impl Default for CertificateRequest {
    fn default() -> Self {
        Self::new()
    }
}
