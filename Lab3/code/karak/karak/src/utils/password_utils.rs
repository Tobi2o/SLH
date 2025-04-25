//! Hachage et vérification des mots de passe

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHashString, PasswordVerifier, SaltString},
    Argon2, PasswordHasher,
};
use derive_more::derive::Display;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::LazyLock};

static DEFAULT_HASHER: LazyLock<Argon2<'static>> = LazyLock::new(|| Argon2::default());

/// Le hash d'un mot de passe vide, à utiliser quand l'utilisateur n'existe pas
/// pour éviter une attaque par canal auxiliaire
static EMPTY_HASH: LazyLock<PWHash> = LazyLock::new(|| hash(""));

/// Un mot de passe haché
#[derive(Clone, Debug, Display)]
pub struct PWHash(PasswordHashString);

impl std::hash::Hash for PWHash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state)
    }
}

impl Serialize for PWHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PWHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let hash = PasswordHashString::from_str(&s)
            .map_err(|_| <D::Error as serde::de::Error>::custom("Invalid PHC string"))?;
        Ok(PWHash(hash))
    }
}

/// Calcule un haché a partir d'un mot de passe en clair, en choisissant un sel au hasard
pub fn hash(password: &str) -> PWHash {
    // Générer un sel aléatoire
    let salt = SaltString::generate(&mut OsRng);

    // Hacher le mot de passe avec le sel généré
    let hash = DEFAULT_HASHER
        .hash_password(password.as_bytes(), &salt)
        .expect("Le hachage du mot de passe ne devrait pas échouer avec des paramètres valides");

    PWHash(hash.serialize())
}

/// Vérifie si le mot de passe correspond au hash stocké.
/// 
/// Si un hash n'est pas fourni, on doit quand même tester
/// le mot de passe avec un faux hash pour éviter une timing
/// attack.
pub fn verify(password: &str, maybe_hash: Option<&PWHash>) -> bool {
    match maybe_hash {
        Some(hash) => DEFAULT_HASHER.verify_password(password.as_bytes(), &hash.0.password_hash()).is_ok(),
        None => {
            // Vérification avec un faux hash pour éviter les attaques par timing
            let _ = DEFAULT_HASHER.verify_password(password.as_bytes(), &EMPTY_HASH.0.password_hash());
            false
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;


    /// Vérifie qu’un mot de passe incorrect ne correspond pas au hachage.
    #[test]
    fn test_verification_mot_de_passe_incorrect() {
        let hash = hash("MotDePasseCorrect");
        assert!(!verify("MotDePasseFaux", Some(&hash)), "Un mot de passe incorrect ne doit pas être validé");
    }
    
    /// Vérifie la correspondance entre un mot de passe correct et son hachage.
    #[test]
    fn test_verification_mot_de_passe_correct() {
        let mot_de_passe = "MotDePasseSécurisé!";
        let hash = hash(mot_de_passe);
        assert!(verify(mot_de_passe, Some(&hash)), "Le mot de passe correct doit être validé avec succès");
    }

    /// Vérifie que le hachage fonctionne avec un mot de passe vide.
    #[test]
    fn test_hachage_mot_de_passe_vide() {
        let hash = hash("");
        assert!(!hash.0.to_string().is_empty(), "Le hachage d'un mot de passe vide ne doit pas être vide");
    }

    /// Vérifie que deux hachages du même mot de passe sont différents (salts aléatoires).
    #[test]
    fn test_hachage_avec_sels_differents() {
        let hash1 = hash("MotDePasse123!");
        let hash2 = hash("MotDePasse123!");
        assert_ne!(hash1.0.to_string(), hash2.0.to_string(), "Deux hachages du même mot de passe ne doivent pas être identiques");
    }


    /// Vérifie que les caractères Unicode sont correctement gérés.
    #[test]
    fn test_hachage_mot_de_passe_unicode() {
        let mot_de_passe = "🔒安全123";
        let hash = hash(mot_de_passe);
        assert!(verify(mot_de_passe, Some(&hash)), "Les caractères Unicode doivent être correctement hachés et vérifiés");
        assert!(!verify("FauxMotDePasse", Some(&hash)), "Un mot de passe incorrect ne doit pas être validé");
    }

    /// Vérifie la gestion des mots de passe vides.
    #[test]
    fn test_verification_mot_de_passe_vide() {
        let hash = hash("");
        assert!(verify("", Some(&hash)), "Un mot de passe vide doit être validé avec son propre hachage");
        assert!(!verify("NonVide", Some(&hash)), "Un mot de passe vide ne doit pas être validé avec un hachage différent");
    }

    /// Vérifie que la vérification échoue pour un utilisateur inexistant.
    #[test]
    fn test_verification_utilisateur_inexistant() {
        assert!(!verify("nimportequoi", None), "Un mot de passe ne doit pas être accepté pour un utilisateur inexistant");
        assert!(!verify("", None), "Un mot de passe vide ne doit pas être accepté pour un utilisateur inexistant");
    }



    /// Vérifie que la vérification du mot de passe est effectuée en temps constant (anti-timing attack).
    #[test]
    fn test_protection_contre_les_attaques_par_timing() {
        use std::time::{Duration, Instant};

        /// Fonction utilitaire pour mesurer le temps d'exécution de la vérification.
        fn mesurer_temps_verification(mot_de_passe: &str, hash_opt: Option<&PWHash>) -> Duration {
            let debut = Instant::now();
            let _ = verify(mot_de_passe, hash_opt);
            debut.elapsed()
        }

        let hash = hash("MotDePasseTest");

        const REPETITIONS: u32 = 20;
        let mut temps_utilisateur_existant = Vec::with_capacity(REPETITIONS as usize);
        let mut temps_utilisateur_inexistant = Vec::with_capacity(REPETITIONS as usize);

        for _ in 0..REPETITIONS {
            temps_utilisateur_existant.push(mesurer_temps_verification("MauvaisMotDePasse", Some(&hash)));
            temps_utilisateur_inexistant.push(mesurer_temps_verification("MauvaisMotDePasse", None));
        }

        let moyenne_existant: Duration = temps_utilisateur_existant.iter().sum::<Duration>() / REPETITIONS;
        let moyenne_inexistant: Duration = temps_utilisateur_inexistant.iter().sum::<Duration>() / REPETITIONS;

        let ratio = moyenne_existant.as_nanos() as f64 / moyenne_inexistant.as_nanos() as f64;
        assert!(
            0.6 < ratio && ratio < 1.4,
            "Les temps de vérification doivent être similaires pour un utilisateur existant et inexistant afin d'éviter une attaque par timing (Ratio observé : {ratio})"
        );
    }

    /// Vérifie que tous les hachages suivent bien le format PHC
    #[test]
    fn test_format_hachage_valide() {
        let hash = hash("motdepasse_test");
        let hash_str = hash.0.to_string();
        assert!(hash_str.starts_with("$argon2"), "Le hash doit respecter le format PHC");
    }

    /// Vérifie que la sérialisation et désérialisation JSON fonctionnent correctement
    #[test]
    fn test_serialisation_deserialisation_hash() {
        let hash = hash("mot_de_passe_test");
        let serialise = serde_json::to_string(&hash).expect("La sérialisation ne devrait pas échouer");
        let deserialise: PWHash = serde_json::from_str(&serialise).expect("La désérialisation ne devrait pas échouer");

        assert!(verify("mot_de_passe_test", Some(&deserialise)), "Le hash sérialisé puis désérialisé doit rester valide");
    }

}

