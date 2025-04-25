use regex::Regex;

/// Validates if the given email address is properly formatted using the `regex` crate.
pub fn valid_email(em: &str) -> bool {
    regex::Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
        .unwrap()
        .is_match(em)
}

/// Ensures the provided name consists only of alphabetic characters, spaces, and dashes, adhering to a length constraint.
pub fn valid_name(nm: &str) -> bool {
    !nm.is_empty()
        && nm.len() <= 50
        && nm.chars().all(|ch| ch.is_alphabetic() || ch.is_whitespace() || ch == '-')
}

/// Confirms that the given ID is alphanumeric, allows dashes, and matches the required length.
pub fn valid_id(identifier: &str) -> bool {
    if identifier.len() != 36 {
        return false;
    }
    
    let uuid_pattern = Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$").unwrap();
    uuid_pattern.is_match(&identifier.to_lowercase())
}

/// Checks if the optional JSON value is a boolean, returning `false` if invalid or absent.
pub fn valid_bool(val: Option<&serde_json::Value>) -> bool {
    match val {
        Some(v) => v.is_boolean(),
        None => false,
    }
}

/// Validates text fields to ensure they are non-empty and within a specified maximum length.
pub fn valid_text(txt: &str, max_len: usize) -> bool {
    !txt.is_empty() && txt.len() <= max_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email() {
        assert!(valid_email("test@example.com"));
        assert!(valid_email("user.name+tag+sorting@example.com"));
        assert!(!valid_email("plainaddress"));
        assert!(!valid_email("@missingusername.com"));
        assert!(!valid_email("username@.com"));
        assert!(!valid_email("username@domain@domain.com"));
    }

    #[test]
    fn test_valid_name() {
        assert!(valid_name("John Doe"));
        assert!(valid_name("Jane"));
        assert!(valid_name("Jean-Claude")); 
        assert!(!valid_name("John123")); 
        assert!(!valid_name("")); 
        assert!(!valid_name("A".repeat(51).as_str())); 
    }

    #[test]
    fn test_valid_id() {
        assert!(valid_id("123e4567-e89b-12d3-a456-426614174000")); // UUID valide
        assert!(!valid_id("123e4567e89b12d3a456426614174000")); // Manque des tirets
        assert!(!valid_id("123e4567-e89b-12d3-a456-42661417400X")); // Caractère invalide
        assert!(!valid_id("short-id")); // Trop court
    }

    #[test]
    fn test_valid_bool() {
        assert!(valid_bool(Some(&serde_json::Value::Bool(true))));
        assert!(valid_bool(Some(&serde_json::Value::Bool(false))));
        assert!(!valid_bool(Some(&serde_json::Value::String("true".to_string()))));
        assert!(!valid_bool(None));
    }

    #[test]
    fn test_valid_text() {
        assert!(valid_text("This is a valid text.", 50));
        assert!(!valid_text("", 50));
        assert!(!valid_text("A".repeat(51).as_str(), 50));
        assert!(valid_text("Short text", 10));
    }
}