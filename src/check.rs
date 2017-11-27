use level::Level;
use std::fmt;

// #[derive(PartialEq, Eq, Ord, Debug, Clone)]
// pub enum Check {
//     Empty(Level, String),
//     Unreadable(Level, String),
//     TooSmall(Level, String),
//     TooBig(Level, String),
// }
//
// impl fmt::Display for Check {
//     fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
//         match self {
//             &Check::Empty(ref level, ref message) |
//             &Check::Unreadable(ref level, ref message) |
//             &Check::TooSmall(ref level, ref message) |
//             &Check::TooBig(ref level, ref message) => write!(out, "{} {}", level, message),
//         }
//     }
// }
//
// impl cmp::PartialOrd for Check {
//     fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
//         self.0.cmp(other.0)
//     }
// }

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
