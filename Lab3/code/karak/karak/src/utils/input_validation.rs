use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zxcvbn::zxcvbn;
use zxcvbn::Score;
use regex::Regex;
use inquire::Text;


/// Critères de validation :
/// - Longueur : entre **8 et 72 caractères**.
/// - Ne doit **pas être trop similaire au nom d'utilisateur**.
/// - Doit **obtenir un score suffisant avec `zxcvbn`**.
/// - Ne doit **pas être composé uniquement de chiffres**.
/// 
/// This function checks if the given password is valid
/// Returns true if the password is strong enough, false otherwise
fn password_validation(password: &str, username: &str) -> bool {
    // Vérification de la longueur du mot de passe
    if password.len() < 8 || password.len() > 72 {
        return false;
    }

    // Interdiction d'utiliser un mot de passe trop proche du nom d'utilisateur
    if password.eq_ignore_ascii_case(username) {
        return false;
    }

    // Interdiction des mots de passe entièrement numériques
    if password.chars().all(|c| c.is_numeric()) {
        return false;
    }

    // Vérification du score de sécurité avec `zxcvbn`
    let estimate = zxcvbn(password, &[username]);
    if estimate.score() < Score::Three {
        return false;
    }

    true
}

/// Interactively prompts the user for a password
pub fn password_input_validation(username: &str) -> String {
    let mut tentative = 0;

    loop {
        let password = inquire::Password::new("Entrez votre mot de passe :")
            .with_help_message(
                "Le mot de passe doit contenir entre 8 et 72 caractères et ne pas être uniquement numérique.",
            )
            .prompt()
            .expect("Erreur lors de la saisie du mot de passe");

        if password_validation(&password, username) {
            return password;
        }

        println!("\nLe mot de passe est trop faible. Veuillez réessayer.\n");
        println!("Voici quelques raisons possibles du rejet :");

        let mut raisons: Vec<String> = Vec::new(); // Le `Vec` doit contenir des `String`
        if password.len() < 8 {
            raisons.push("- Il est trop court (minimum 8 caractères).".to_string());
        }
        if password.len() > 72 {
            raisons.push("- Il est trop long (maximum 72 caractères).".to_string());
        }
        if password.eq_ignore_ascii_case(username) {
            raisons.push("- Il est trop similaire à votre nom d'utilisateur.".to_string());
        }
        if password.chars().all(|c| c.is_numeric()) {
            raisons.push("- Il est composé uniquement de chiffres.".to_string());
        }

        let estimate = zxcvbn(&password, &[username]);
        if estimate.score() < Score::Three {
            raisons.push(format!(
                "- Il est trop faible (score : {}/4).",
                estimate.score()
            ));
            if let Some(feedback) = estimate.feedback() {
                if let Some(warning) = feedback.warning() {
                    raisons.push(format!("- {}", warning));
                }
                for suggestion in feedback.suggestions() {
                    raisons.push(format!("- {}", suggestion));
                }
            }
        }

        for raison in raisons {
            println!("{}", raison);
        }

        tentative += 1;

        if tentative == 5 {
            println!("\nAttention : Vous avez échoué 5 fois. Assurez-vous de choisir un mot de passe conforme.");
        }
    }
}


#[derive(Debug, Clone, Copy, Display, Error)]
pub struct InvalidInput;

/// Wrapper type for a username thas has been validated
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash, Display, Clone)]
pub struct Username(String);

impl TryFrom<String> for Username {
    type Error = InvalidInput;

    fn try_from(username: String) -> Result<Self, Self::Error> {
        username_validation(&username)?;
        Ok(Self(username))
    }
}

impl TryFrom<&str> for Username {
    type Error = InvalidInput;

    fn try_from(username: &str) -> Result<Self, Self::Error> {
        username_validation(username)?;
        Ok(Self(username.to_owned()))
    }
}

impl AsRef<str> for Username {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Vérifie si un nom d'utilisateur est valide.
/// - Doit contenir entre **3 et 30 caractères**.
/// - Peut contenir **lettres, chiffres, `_`, `-`, et `.`**.
/// - Ne peut **pas commencer ni terminer par un symbole**.
/// - Interdit **les doublons de caractères spéciaux (`..`, `__`, `--`)**.
/// - Empêche **les noms réservés (`admin`, `root`, etc.).**
fn username_validation(username: &str) -> Result<(), InvalidInput> {
    // Vérification de la longueur
    if username.len() < 3 || username.len() > 30 {
        return Err(InvalidInput);
    }

    // Expression régulière pour valider le format
    let username_regex = Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]$").unwrap();
    if !username_regex.is_match(username) {
        return Err(InvalidInput);
    }

    // Interdiction des doubles caractères spéciaux (`..`, `__`, `--`)
    let invalid_patterns = ["..", "__", "--"];
    if invalid_patterns.iter().any(|p| username.contains(p)) {
        return Err(InvalidInput);
    }

    // Liste de noms interdits
    let forbidden_usernames = ["admin", "root", "superuser", "test", "guest"];
    if forbidden_usernames.contains(&username.to_lowercase().as_str()) {
        return Err(InvalidInput);
    }

    Ok(())
}

/// Demande à l'utilisateur de saisir un nom d'utilisateur valide.
pub fn username_input_validation(message: &str) -> Result<Username, InvalidInput> {
    loop {
        let username = Text::new(message)
            .with_help_message(
                "Le nom d'utilisateur doit contenir entre 3 et 30 caractères alphanumériques et peut inclure `_`, `-`, ou `.` (mais pas en double)."
            )
            .prompt()
            .expect("Erreur lors de la saisie du nom d'utilisateur");

        match Username::try_from(username.clone()) {
            Ok(valid_username) => return Ok(valid_username),
            Err(_) => {
                println!("\n❌ Nom d'utilisateur invalide. Vérifiez les critères suivants :");
                println!("- Longueur entre 3 et 30 caractères.");
                println!("- Peut contenir des lettres, chiffres, `_`, `-`, ou `.`.");
                println!("- Ne peut pas commencer ou terminer par `_`, `-`, ou `.`.");
                println!("- Pas de `..`, `__` ou `--`.");
                println!("- Ne peut pas être un nom réservé (`admin`, `root`, `test`, etc.).");
            }
        }
    }
}

/// Wrapper type for an AVS number that has been validated
#[derive(Debug, Serialize, Deserialize, Hash, Clone)]
pub struct AVSNumber(String);

impl TryFrom<String> for AVSNumber {
    type Error = InvalidInput;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if validate_avs_number(&value) {
            Ok(AVSNumber(value))
        } else {
            Err(InvalidInput)
        }
    }
}

impl TryFrom<&str> for AVSNumber {
    type Error = InvalidInput;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if validate_avs_number(value) {
            Ok(AVSNumber(value.to_owned()))
        } else {
            Err(InvalidInput)
        }
    }
}

impl std::fmt::Display for AVSNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let digits: String = self.0.chars().filter(|c| c.is_digit(10)).collect();

        if digits.len() == 13 {
            write!(
                f,
                "{}.{}.{}.{}",
                &digits[0..3], &digits[3..7], &digits[7..11], &digits[11..13]
            )
        } else {
            write!(f, "{}", self.0)
        }
    }
}






/// Vérifie si un numéro AVS est valide.
/// - Format attendu : `756.XXXX.XXXX.XX` ou `756XXXXXXXXXX`
/// - Vérifie la somme de contrôle avec **Modulo 10**.
fn validate_avs_number(avs_number: &str) -> bool {
    let avs_regex = Regex::new(r"^756\.?\d{4}\.?\d{4}\.?\d{2}$").unwrap();
    if !avs_regex.is_match(avs_number) {
        return false;
    }

    // Extraction des chiffres du numéro AVS
    let digits: Vec<u32> = avs_number.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() != 13 {
        return false;
    }

    // Vérification de la somme de contrôle avec l'algorithme Modulo 10
    let mut sum = 0;
    for (i, &digit) in digits.iter().enumerate() {
        sum += if i % 2 == 0 { digit * 2 } else { digit };
    }

    sum % 10 == 0
}


#[cfg(test)]
mod tests {
    use super::*;

    /// Vérifie que la validation des mots de passe fonctionne correctement.
    #[test]
    fn test_validation_mot_de_passe() {
        // Cas valides
        assert!(password_validation("MotDePasse123!", "Utilisateur"));
        assert!(password_validation("Passw0rd!SuperSecurise", "different_user"));

        // Longueur invalide
        assert!(!password_validation("court", "Utilisateur"));
        assert!(!password_validation(&"a".repeat(73), "Utilisateur")); // Trop long

        // Trop similaire au nom d'utilisateur
        assert!(!password_validation("Utilisateur", "Utilisateur"));
        assert!(!password_validation("UTILISATEUR", "Utilisateur"));

        // Mots de passe faibles
        assert!(!password_validation("password123", "Utilisateur"));
        assert!(!password_validation("qwerty123", "Utilisateur"));
        assert!(!password_validation("12345678", "Utilisateur"));

        // Composé uniquement de chiffres
        assert!(!password_validation("1234567890", "Utilisateur"));
    }

    /// Vérifie que la validation des noms d'utilisateur est correcte.
    #[test]
    fn test_validation_nom_utilisateur() {
        // Cas valides
        assert!(username_validation("utilisateur_01").is_ok());
        assert!(username_validation("Jean.Dupont").is_ok());
        assert!(username_validation("test-user").is_ok());

        // Trop long ou trop court
        assert!(username_validation("ab").is_err()); // Trop court
        assert!(username_validation(&"a".repeat(31)).is_err()); // Trop long

        // Caractères invalides
        assert!(username_validation("utilisateur@name").is_err());
        assert!(username_validation("utilisateur nom").is_err());
        assert!(username_validation("_utilisateur").is_err());
        assert!(username_validation("utilisateur_").is_err());

        // Double caractères spéciaux interdits
        assert!(username_validation("utilisateur..nom").is_err());
        assert!(username_validation("utilisateur__nom").is_err());
        assert!(username_validation("utilisateur--nom").is_err());

        // Noms réservés interdits
        assert!(username_validation("admin").is_err());
        assert!(username_validation("root").is_err());
        assert!(username_validation("superuser").is_err());
        assert!(username_validation("test").is_err());
        assert!(username_validation("guest").is_err());
    }

    /// Vérifie que la conversion TryFrom fonctionne pour les noms d'utilisateur.
    #[test]
    fn test_conversion_nom_utilisateur() {
        // Cas valides
        assert!(Username::try_from("nom_utilisateur").is_ok());
        assert!(Username::try_from(String::from("user-123")).is_ok());

        // Cas invalides
        assert!(Username::try_from("nom@utilisateur").is_err());
        assert!(Username::try_from(String::from("")).is_err());
        assert!(Username::try_from(String::from("root")).is_err()); // Nom interdit
    }

    /// Vérifie que la conversion TryFrom fonctionne pour les numéros AVS.
    #[test]
    fn test_affichage_numero_avs() {
        let avs = AVSNumber::try_from("7561234567897".to_string()).unwrap();
        assert_eq!(avs.to_string(), "756.1234.5678.97");
    
        let avs = AVSNumber::try_from("756.1234.5678.97".to_string()).unwrap();
        assert_eq!(avs.to_string(), "756.1234.5678.97");
    }

    /// Vérifie que la validation du numéro AVS fonctionne correctement.
    #[test]
    fn test_validation_numero_avs() {
        // Numéros AVS valides
        assert!(validate_avs_number("756.1234.5678.97"));
        assert!(validate_avs_number("7561234567897")); // Sans points
    
        // Formats incorrects
        assert!(!validate_avs_number("756.1234.5678")); // Trop court
        assert!(!validate_avs_number("abc.1234.5678.90")); // Préfixe invalide
        assert!(!validate_avs_number("756.abcd.5678.90")); // Contient des lettres
    
        // Vérification d'un mauvais chiffre de contrôle
        assert!(!validate_avs_number("756.1234.5678.00"));
        assert!(!validate_avs_number("7560000000009")); // Mauvais contrôle Modulo 10
    }
    
} 