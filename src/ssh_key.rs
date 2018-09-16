use nom;
use nom::be_u32;
use std::fmt;

#[derive(PartialEq, Eq, Debug)]
pub enum Algorithm {
    Unknown,
    Ed25519(Vec<u8>),
    Rsa(Vec<u8>),
    Ecdsa(String, Vec<u8>),
    Dsa(Vec<u8>),
}

impl fmt::Display for Algorithm {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Algorithm::Ed25519(_) => write!(out, "ed25519"),
            Algorithm::Rsa(_) => write!(out, "rsa"),
            Algorithm::Ecdsa(ref curve, _) => write!(out, "ecdsa, curve {}", curve),
            Algorithm::Dsa(_) => write!(out, "dsa"),
            _ => write!(out, "unknown"),
        }
    }
}

#[derive(Debug)]
pub struct SshKey {
    pub algorithm: Algorithm,
    pub comment: Option<String>,
    pub is_encrypted: bool,
    pub is_public: bool,
}

impl SshKey {
    pub fn new() -> Self {
        Self {
            algorithm: Algorithm::Unknown,
            comment: None,
            is_encrypted: false,
            is_public: false,
        }
    }

    pub fn is_pair(&self, other: &SshKey) -> bool {
        if self.is_public == other.is_public {
            return false;
        }
        match self.algorithm {
            Algorithm::Ed25519(ref point) => match other.algorithm {
                Algorithm::Ed25519(ref point2) => point == point2,
                _ => false,
            },
            Algorithm::Rsa(ref modulus) => match other.algorithm {
                Algorithm::Rsa(ref modulus2) => modulus == modulus2,
                _ => false,
            },
            Algorithm::Dsa(ref p_integer) => match other.algorithm {
                Algorithm::Dsa(ref p_integer2) => p_integer == p_integer2,
                _ => false,
            },
            Algorithm::Ecdsa(ref curve, ref point) => match other.algorithm {
                Algorithm::Ecdsa(ref curve2, ref point2) => curve == curve2 && point == point2,
                _ => false,
            },
            _ => false,
        }
    }
}

fn bit_count(field: &[u8]) -> usize {
    field.len() * 8
}

impl fmt::Display for SshKey {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        if self.is_public {
            output.push_str("public ");
        } else {
            output.push_str("private ");
        }
        output.push_str("ssh key (");
        output.push_str(&format!("{}", self.algorithm));
        if !self.is_encrypted {
            match self.algorithm {
                Algorithm::Rsa(ref modulus) => {
                    output.push_str(&format!(", {} bits", bit_count(modulus)));
                }
                Algorithm::Dsa(ref p_integer) => {
                    output.push_str(&format!(", {} bits", bit_count(p_integer)));
                }
                _ => (),
            }
        }
        if !self.is_public {
            output.push_str(", ");
            if self.is_encrypted {
                output.push_str("encrypted");
            } else {
                output.push_str("not encrypted");
            }
        }
        output.push_str(")");
        write!(out, "{}", output)
    }
}

impl Default for SshKey {
    fn default() -> Self {
        Self::new()
    }
}

named!(
    nom_ed25519<(&[u8])>,
    do_parse!(_cipher_name: length_bytes!(be_u32) >> point: length_bytes!(be_u32) >> (point))
);

named!(
    nom_rsa<(&[u8])>,
    do_parse!(
        _cipher_name: length_bytes!(be_u32)
            >> _ver_or_exp: length_bytes!(be_u32)
            >> modulus: length_bytes!(be_u32)
            >> (&modulus[1..])
    )
);

named!(
    nom_dss<(&[u8])>,
    do_parse!(
        _cipher_name: length_bytes!(be_u32) >> p_integer: length_bytes!(be_u32) >> (&p_integer[1..])
    )
);

named!(
    nom_ecdsa<(&[u8], &[u8])>,
    do_parse!(
        _key_type: length_bytes!(be_u32)
            >> curve: length_bytes!(be_u32)
            >> point: length_bytes!(be_u32)
            >> (curve, point)
    )
);

pub fn peek_algorithm(is_encrypted: bool, key_bytes: &[u8]) -> Result<Algorithm, String> {
    if key_bytes.len() < 4 {
        return Err("Too short to be a valid ssh key".into());
    }
    let mut algorithm = Algorithm::Unknown;
    // Skip 4-byte length indicator
    let algorithm_name = &key_bytes[4..];
    if algorithm_name.starts_with(b"ssh-ed25519") {
        algorithm = Algorithm::Ed25519(vec![]);
    }
    if algorithm_name.starts_with(b"ecdsa-sha2-nistp256") {
        algorithm = Algorithm::Ecdsa("nistp256".into(), vec![]);
    }
    if algorithm_name.starts_with(b"ecdsa-sha2-nistp384") {
        algorithm = Algorithm::Ecdsa("nistp384".into(), vec![]);
    }
    if algorithm_name.starts_with(b"ecdsa-sha2-nistp521") {
        algorithm = Algorithm::Ecdsa("nistp521".into(), vec![]);
    }
    if algorithm_name.starts_with(b"ssh-dss") {
        algorithm = Algorithm::Dsa(vec![]);
    }
    if algorithm_name.starts_with(b"ssh-rsa") {
        algorithm = Algorithm::Rsa(vec![]);
    }
    if is_encrypted {
        return Ok(algorithm);
    }
    if algorithm_name.starts_with(b"ssh-ed25519") {
        return match nom_ed25519(key_bytes) {
            Ok((_tail, point)) => Ok(Algorithm::Ed25519(point.to_owned())),
            Err(nom::Err::Error(_e)) | Err(nom::Err::Failure(_e)) => Err("Parse error".into()),
            Err(nom::Err::Incomplete(_needed)) => Err("Didn't fully parse".into()),
        };
    }
    if algorithm_name.starts_with(b"ssh-rsa") {
        return match nom_rsa(key_bytes) {
            Ok((_tail, modulus)) => Ok(Algorithm::Rsa(modulus.to_owned())),
            Err(nom::Err::Error(_e)) | Err(nom::Err::Failure(_e)) => Err("Parse error".into()),
            Err(nom::Err::Incomplete(_needed)) => Err("Didn't fully parse".into()),
        };
    }
    if algorithm_name.starts_with(b"ssh-dss") {
        return match nom_dss(key_bytes) {
            Ok((_tail, p_integer)) => Ok(Algorithm::Dsa(p_integer.to_owned())),
            Err(nom::Err::Error(_e)) | Err(nom::Err::Failure(_e)) => Err("Parse error".into()),
            Err(nom::Err::Incomplete(_needed)) => Err("Didn't fully parse".into()),
        };
    }
    if algorithm_name.starts_with(b"ecdsa-sha2-nistp") {
        return match nom_ecdsa(key_bytes) {
            Ok((_tail, (curve, point))) => Ok(Algorithm::Ecdsa(
                String::from_utf8_lossy(curve).into(),
                point.to_owned(),
            )),
            Err(nom::Err::Error(_e)) | Err(nom::Err::Failure(_e)) => Err("Parse error".into()),
            Err(nom::Err::Incomplete(_needed)) => Err("Didn't fully parse".into()),
        };
    }
    Ok(algorithm)
}

#[test]
fn test_is_pair() {
    let mut rsa_priv_1: SshKey = Default::default();
    rsa_priv_1.algorithm = Algorithm::Rsa(vec![1, 2, 3]);
    assert!(!rsa_priv_1.is_pair(&rsa_priv_1));

    let mut rsa_pub_1: SshKey = Default::default();
    rsa_pub_1.is_public = true;
    rsa_pub_1.algorithm = Algorithm::Rsa(vec![1, 2, 3]);
    assert!(rsa_priv_1.is_pair(&rsa_pub_1));
    assert!(rsa_pub_1.is_pair(&rsa_priv_1));

    let mut dsa_pub_1: SshKey = Default::default();
    dsa_pub_1.is_public = true;
    dsa_pub_1.algorithm = Algorithm::Dsa(vec![1, 2, 3]);
    assert!(!dsa_pub_1.is_pair(&rsa_priv_1));

    let mut rsa_pub_2: SshKey = Default::default();
    rsa_pub_2.is_public = true;
    rsa_pub_2.algorithm = Algorithm::Rsa(vec![4, 5, 6]);
    assert!(!rsa_pub_2.is_pair(&rsa_priv_1));
    assert!(!rsa_priv_1.is_pair(&rsa_pub_2));

    let mut dsa_priv_2: SshKey = Default::default();
    dsa_priv_2.algorithm = Algorithm::Dsa(vec![4, 5, 6]);
    assert!(!dsa_priv_2.is_pair(&dsa_priv_2));
    assert!(!dsa_priv_2.is_pair(&rsa_pub_1));
    assert!(!dsa_priv_2.is_pair(&rsa_priv_1));

    let mut dsa_pub_2: SshKey = Default::default();
    dsa_pub_2.is_public = true;
    dsa_pub_2.algorithm = Algorithm::Dsa(vec![4, 5, 6]);
    assert!(dsa_pub_2.is_pair(&dsa_priv_2));
    assert!(dsa_priv_2.is_pair(&dsa_pub_2));
    assert!(!dsa_pub_2.is_pair(&rsa_priv_1));

    let mut ecdsa_priv_1: SshKey = Default::default();
    ecdsa_priv_1.algorithm = Algorithm::Ecdsa("nistp384".into(), vec![1, 2, 3]);
    assert!(!ecdsa_priv_1.is_pair(&rsa_priv_1));
    let mut ecdsa_pub_1: SshKey = Default::default();
    ecdsa_pub_1.is_public = true;
    ecdsa_pub_1.algorithm = Algorithm::Ecdsa("nistp384".into(), vec![1, 2, 3]);
    assert!(ecdsa_priv_1.is_pair(&ecdsa_pub_1));
    assert!(ecdsa_pub_1.is_pair(&ecdsa_priv_1));

    let mut ed25519_priv_1: SshKey = Default::default();
    ed25519_priv_1.algorithm = Algorithm::Ed25519(vec![7, 8, 9]);
    assert!(!ed25519_priv_1.is_pair(&rsa_priv_1));
    let mut ed25519_pub_1: SshKey = Default::default();
    ed25519_pub_1.is_public = true;
    ed25519_pub_1.algorithm = Algorithm::Ed25519(vec![7, 8, 9]);
    assert!(ed25519_priv_1.is_pair(&ed25519_pub_1));
    assert!(ed25519_pub_1.is_pair(&ed25519_priv_1));
}
