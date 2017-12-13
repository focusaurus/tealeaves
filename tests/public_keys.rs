extern crate tealeaves;

use tealeaves::parse::public_key;

#[test]
fn public_ed25519() {
    let key_bytes = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDZZL7FhUAK5ObLFAMHIV8Pm1F9kWfGrTeXTj61g/ETG Tealeaves test ED25519 SSH Key 1\n";
    match public_key(key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("ed25519".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment,
                       Some("Tealeaves test ED25519 SSH Key 1".to_string()));
            assert_eq!(ssh_key.key_length, None);
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_rsa_1024() {
    let key_bytes = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCjR11YkCFYeJOQKGn1JMZJOFbDrUbyju7nk6Itoz39DGkPZ6mbOs7z3Mh39K2Y+5H+tsOdJaKIca1zoDvHFDpVnejrIuPKaacspgWaf/VSaHjeltKdgvIie+Awjvsen1+/JWwR815+6CE5YZgLIIZmRj9IwRWohKq8G6dwXzKTpw== unit test comment\n";
    match public_key(key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("rsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(1024));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_rsa_2048() {
    let key_bytes = b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwWx+Mhpajv3nvVs/vg6+3qN5KQ+DC8fznprHw/sKqB4gMRs3xRCeNveYPWXrtT5f1Cr64Wt3R7t9XbLISd7g4vsJ9Oe5YG3WsyM3z/LGqneyyCBDFhQzTPSUet3GNPqpxbakpNjYieJVEbDHEhqW/SwroTG+ua54gmWLnA3ULxLgAistlv7UtT0vJkO2Xr/Oed9NNPaYSuZReYOoLmRRLumxEpP+0FrTGS4BlvkQyWIz0Wq6rI//XjbNMUitRrcp2U6TuTtR7f9FjVlJjgxcJuCd5IGxNlIHjtcJN40/KtdF9ZFCoU0GnM0eGj2Gbw2pbasOP1rHhxFg56j3z++R1 unit test comment\n";
    match public_key(key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("rsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(2048));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_dsa() {
    let key_bytes = b"ssh-dss AAAAB3NzaC1kc3MAAACBAL0EDUUiLIFjOqHjvJ8bM59sHZWtLGlQoV032shjlsS/hQlux8tkJjRMh7VWFUt9kOVqfeTchKEdGVGPtKb0iMc/gGaCuSX6PQQ5NSRTWDAjPofprz2LAi9ZwWSh8o7s+sfoZB78JEO8PQav7kEnFxWJZ1n02d4N4BHakv7Q62HJAAAAFQDGRB84tU9W05EZDwzveVtbyEiZSQAAAIBwI2+r1qTTIIKgmrkN4zDhYb8Zj6KIaIwpFBFWU0oxbUm6F69AzmOEZ19HaSOhkts8FX9X0BiSwLhrsMKh0Xq3uLZ6TM58sUTmI662m4xiEen0ClYh4atgK8/dd4VtgezLoo2QValcxwLNBn5BXgT+Qg9B9+339AKZ1LeJxyNY6AAAAIB1jjKso/Qa7WR8DF8Sm8ca/ShnvBysuwIPn/oaS0is9XaZJGwrnSzM0VpiE+EY8WW5CRVW06VwDn4nkFFbs0vHd6JAqhUGmgyF1OLqcvzwcl7yubSCggUh6EwzbDSmPHO9v/hQp15LbcdTJ9iep4RtXnY5OH4TSNErRouJaJw8vQ== unit test comment\n";
    match public_key(key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("dsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(1024));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_ecdsa_256() {
    let key_bytes = b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBD3I/jIQKztozlWH540Gu5RB1Wy+c7Fe6Vi+rXztmcUWCX5UtWFtNsed3KC/N7tSrcW5SouAUuvH7RkfuTAOWWY= unit test comment\n";
    match public_key(key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("ecdsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(256));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_ecdsa_384() {
    let key_bytes = b"ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBMrJPQWUkTA3UBW9gMpkfpkMXk3bbs6j+f6wnoLacP29712m4nV+TLaU6pB2SzzBxArnsHeSz0hcBu6RJUY3Yxn+8ZdsFljgiBzlIqizdD4yHNq4fQUbrMb2+2kpk5+pYg== unit test comment\n";
    match public_key(key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("ecdsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(384));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}

#[test]
fn public_ecdsa_521() {
    let key_bytes = b"ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBABhKlTL06RBC2Gn1UOE8+qcrhJx3JgmvvFuJcLlhoeDxGwVplgD6mMtGFEKtQkk3eCAz9pqpR1iHs0ke6Y4IrT6ggEpcSrc4Pe05uu3BffhIXAxRNRUhZkxHpioG9TQJCvoU+mJXtyJBfCnKqJGdpRMkh9cpMsHBD2Wv96yxaMwvFUduw== unit test comment\n";
    match public_key(key_bytes) {
        Ok(ssh_key) => {
            assert_eq!(ssh_key.algorithm, Some("ecdsa".to_string()));
            assert_eq!(ssh_key.is_public, true);
            assert_eq!(ssh_key.comment, Some("unit test comment".to_string()));
            assert_eq!(ssh_key.key_length, Some(521));
            assert_eq!(ssh_key.is_encrypted, false);
        }
        Err(error) => {
            assert!(false, format!("Failed to parse: {}", error));
        }
    }
}
