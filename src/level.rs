use std::fmt;

#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone)]
pub enum Level {
    Error,
    Warning,
    Ok,
}

impl fmt::Display for Level {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        write!(out,
               "{}",
               match self {
                   &Level::Error => "🔥",
                   &Level::Warning => "⚠️",
                   &Level::Ok => "✓",
               })
    }
}

#[test]
fn test_level_order() {
    assert!(Level::Error < Level::Warning);
    assert!(Level::Warning < Level::Ok);
    assert!(Level::Error < Level::Ok);
    assert!(Level::Ok > Level::Warning);
}

#[test]
fn test_level_display() {
    assert_eq!(format!("{}", Level::Error), "🔥");
    assert_eq!(format!("{}", Level::Warning), "⚠️");
    assert_eq!(format!("{}", Level::Ok), "✓");
}
