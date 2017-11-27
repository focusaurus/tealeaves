use level::Level;
use std::fmt;

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum Kind {
    Empty,
    Unreadable,
    TooSmall,
    TooBig,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Check {
    level: Level,
    pub kind: Kind,
    message: String,
}

impl fmt::Display for Check {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        write!(out, "{} {}", &self.level, &self.message)
    }
}

impl Check {
    pub fn empty() -> Self {
        Self {
            level: Level::Error,
            kind: Kind::Empty,
            message: "is empty".to_string(),
        }
    }

    pub fn unreadable() -> Self {
        Self {
            level: Level::Error,
            kind: Kind::Unreadable,
            message: "missing read permission".to_string(),
        }
    }

    pub fn too_small() -> Self {
        Self {
            level: Level::Warning,
            kind: Kind::TooSmall,
            message: "file size too small".to_string(),
        }
    }

    pub fn too_big() -> Self {
        Self {
            level: Level::Warning,
            kind: Kind::TooBig,
            message: "file size too big".to_string(),
        }
    }
}

#[test]
fn test_check_order() {
    let error = Check::unreadable();
    let warning = Check::too_small();
    assert!(error < warning);
}
