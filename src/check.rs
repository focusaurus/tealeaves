use level::Level;
use std::{cmp,fmt};

#[derive(PartialEq, Eq, Ord, Debug, Clone)]
pub enum Check {
    Empty(Level, String),
    Unreadable(Level, String),
    TooSmall(Level, String),
    TooBig(Level, String),
}

impl fmt::Display for Check {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Check::Empty(ref level, ref message) |
            &Check::Unreadable(ref level, ref message) |
            &Check::TooSmall(ref level, ref message) |
            &Check::TooBig(ref level, ref message) => write!(out, "{} {}", level, message),
        }
    }
}

impl cmp::PartialOrd for Check {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.0.cmp(other.0)
    }
}

/*
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub struct Check {
    level: Level,
    message: String,
}

impl fmt::Display for Check {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        let mut output = String::new();
        output.push_str(match self.level {
                            Level::Error => "🔥",
                            Level::Warning => "⚠️",
                            Level::Ok => "✓",
                        });
        output.push_str(" ");
        output.push_str(&self.message);
        write!(out, "{}", output)
    }
}

impl Check {
    pub fn error(message: &str) -> Self {
        Self {
            message: message.to_string(),
            level: Level::Error,
        }
    }
    pub fn warning(message: &str) -> Self {
        Self {
            message: message.to_string(),
            level: Level::Warning,
        }
    }
    pub fn ok(message: &str) -> Self {
        Self {
            message: message.to_string(),
            level: Level::Ok,
        }
    }
}

#[test]
fn test_check_order() {
    let error = Check::error("");
    let warning = Check::warning("");
    let ok = Check::ok("");
    assert!(error < warning);
    assert!(warning < ok);
    assert!(ok > warning);
    assert!(ok > error);
}
*/
