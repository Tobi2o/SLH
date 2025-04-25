//! Wrapper d'appel à Casbin pour la vérification statique
//! des conventions objet-action

use casbin::CoreApi;
use log::{error, info};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;
use strum::IntoEnumIterator;

use crate::models::{MedicalReport, Role, UserData};

const CONFIG: &str = "access_control/model.conf";
const POLICY: &str = "access_control/policy.csv";

/// Un enforcer Casbin
pub struct Enforcer(casbin::Enforcer);

type CasbinResult = Result<(), AccessDenied>;

/// Une erreur sans détails en cas d'accès refusé
#[derive(Debug, Error)]
#[error("Accès refusé.")]
pub struct AccessDenied;

/// Un contexte contenant une référence à un enforcer et à un sujet.
pub struct Context<'ctx> {
    enforcer: &'ctx Enforcer,
    subject: &'ctx UserData,
}

impl Enforcer {
    pub fn load() -> Result<Self, casbin::Error> {
        let mut enforcer = futures::executor::block_on(casbin::Enforcer::new(CONFIG, POLICY))?;
        futures::executor::block_on(enforcer.load_policy())?;
        Ok(Enforcer(enforcer))
    }

    pub fn with_subject<'ctx>(&'ctx self, subject: &'ctx UserData) -> Context<'ctx> {
        Context {
            enforcer: self,
            subject,
        }
    }
}

impl Context<'_> {
    fn enforce<O>(&self, object: O, action: &str) -> CasbinResult
    where
        O: Serialize + std::fmt::Debug + std::hash::Hash,
    {
        let subject = self.subject;

        info!(
            "Enforcing {}",
            json!({ "sub": subject, "obj": &object, "act": action })
        );
        match self.enforcer.0.enforce((subject, &object, action)) {
            Err(e) => {
                error!("Casbin error: {e:?}");
                Err(AccessDenied)
            }
            Ok(r) => {
                info!("Granted: {r}");
                if r {
                    Ok(())
                } else {
                    Err(AccessDenied)
                }
            }
        }
    }

    pub fn read_data(&self, patient: &UserData) -> CasbinResult {
        self.enforce(patient, "read-data")
    }

    pub fn update_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "update-data")
    }

    pub fn delete_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "delete-data")
    }

    pub fn add_report(&self, patient: &UserData, report: &MedicalReport) -> CasbinResult {
        self.enforce(
            json!({ "patient": patient, "report": report }),
            "add-report",
        )
    }

    pub fn read_report(&self, report: &MedicalReport, patient: &UserData) -> CasbinResult {
        self.enforce(json!({"report": report, "patient": patient}), "read-report")
    }

    pub fn update_report(&self, report: &MedicalReport) -> CasbinResult {
        self.enforce(report, "update-report")
    }

    pub fn update_role(&self, target: &UserData, role: Role) -> CasbinResult {
        self.enforce(json!({ "target": target, "role": role }), "update-role")
    }

    pub fn add_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(json!({"patient": target, "doctor": doctor}), "add-doctor")
    }

    pub fn remove_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(json!({"patient": target, "doctor": doctor}), "remove-doctor")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BloodType, MedicalFolder, PersonalData, ReportID, UserID};
    use crate::utils::input_validation::{AVSNumber, Username};
    use crate::utils::password_utils::hash;
    use std::collections::BTreeSet;
    use test_log::test;
    

    /// Crée un utilisateur avec un rôle et, si nécessaire, un dossier médical.
    fn creer_utilisateur(role: Role, avec_dossier: bool) -> UserData {
        let medical_folder = if avec_dossier {
            Some(MedicalFolder {
                personal_data: PersonalData {
                    avs_number: AVSNumber::try_from("756.1234.5678.97").unwrap(),
                    blood_type: BloodType::A,
                },
                doctors: BTreeSet::new(),
            })
        } else {
            None
        };

        UserData {
            id: UserID::new(),
            role,
            username: Username::try_from("utilisateur_test").unwrap(),
            password: hash("motdepasse"),
            medical_folder,
        }
    }

    /// Génère des cas de test pour les utilisateurs et permissions.
    fn generer_cas_test() -> Vec<(UserData, UserData)> {
        let admin = creer_utilisateur(Role::Admin, false);
        let patient = creer_utilisateur(Role::Patient, true);
        let doctor = creer_utilisateur(Role::Doctor, true);

        // Patient avec un médecin traitant
        let mut patient_avec_medecin = creer_utilisateur(Role::Patient, true);
        if let Some(folder) = &mut patient_avec_medecin.medical_folder {
            folder.doctors.insert(doctor.id);
        }

        vec![
            (admin.clone(), admin.clone()),                  // Admin accédant à ses propres données
            (admin.clone(), patient.clone()),                // Admin accédant aux données d'un patient
            (doctor.clone(), patient_avec_medecin.clone()),  // Médecin accédant à son patient
            (patient.clone(), patient.clone()),              // Patient accédant à ses propres données
            (patient.clone(), admin.clone()),               // Patient essayant d'accéder à l'admin
        ]
    }

    /// Teste les permissions pour lire les données personnelles.
    #[test]
    fn test_permissions_lecture_donnees() {
        let enforcer = Enforcer::load().unwrap();

        for (acteur, cible) in generer_cas_test() {
            let contexte = enforcer.with_subject(&acteur);
            let resultat = contexte.read_data(&cible);

            match acteur.role {
                Role::Admin => {
                    assert!(
                        resultat.is_ok(),
                        "L'administrateur devrait pouvoir lire les données de {:?}",
                        cible.username
                    );
                }
                Role::Doctor => {
                    if cible
                        .medical_folder
                        .as_ref()
                        .map_or(false, |folder| folder.doctors.contains(&acteur.id))
                    {
                        assert!(
                            resultat.is_ok(),
                            "Le médecin devrait pouvoir lire les données de son patient"
                        );
                    } else {
                        assert!(
                            resultat.is_err(),
                            "Le médecin ne devrait pas pouvoir lire les données d'un non-patient"
                        );
                    }
                }
                Role::Patient => {
                    if acteur.id == cible.id {
                        assert!(
                            resultat.is_ok(),
                            "Un utilisateur devrait pouvoir lire ses propres données"
                        );
                    } else {
                        assert!(
                            resultat.is_err(),
                            "Un patient ne devrait pas pouvoir lire les données d'autres utilisateurs"
                        );
                    }
                }
            }
        }
    }

    /// Teste les permissions pour mettre à jour les données personnelles.
    #[test]
    fn test_permissions_mise_a_jour_donnees() {
        let enforcer = Enforcer::load().unwrap();

        for (acteur, cible) in generer_cas_test() {
            let contexte = enforcer.with_subject(&acteur);
            let resultat = contexte.update_data(&cible);

            match acteur.role {
                Role::Admin => {
                    assert!(
                        resultat.is_ok(),
                        "L'administrateur devrait pouvoir modifier les données de {:?}",
                        cible.username
                    );
                }
                Role::Patient => {
                    if acteur.id == cible.id {
                        assert!(
                            resultat.is_ok(),
                            "Un utilisateur devrait pouvoir modifier ses propres données"
                        );
                    } else {
                        assert!(
                            resultat.is_err(),
                            "Un patient ne devrait pas pouvoir modifier les données d'autres utilisateurs"
                        );
                    }
                }
                _ => {
                    assert!(
                        resultat.is_err(),
                        "Seul un admin ou l'utilisateur concerné devrait pouvoir modifier les données"
                    );
                }
            }
        }
    }
    /// Teste les permissions pour supprimer les données personnelles.
    #[test]
    fn test_permissions_suppression_donnees() {
        let enforcer = Enforcer::load().unwrap();

        for (acteur, cible) in generer_cas_test() {
            let contexte = enforcer.with_subject(&acteur);
            let resultat = contexte.delete_data(&cible);

            match acteur.role {
                Role::Admin => {
                    assert!(
                        resultat.is_ok(),
                        "L'administrateur devrait pouvoir supprimer les données de {:?}",
                        cible.username
                    );
                }
                Role::Patient => {
                    if acteur.id == cible.id {
                        assert!(
                            resultat.is_ok(),
                            "Un utilisateur devrait pouvoir supprimer ses propres données"
                        );
                    } else {
                        assert!(
                            resultat.is_err(),
                            "Un patient ne devrait pas pouvoir supprimer les données d'autres utilisateurs"
                        );
                    }
                }
                _ => {
                    assert!(
                        resultat.is_err(),
                        "Seul un admin ou l'utilisateur concerné devrait pouvoir supprimer les données"
                    );
                }
            }
        }
    }

    

    /// Teste les permissions pour ajouter des rapports médicaux.
    #[test]
    fn test_permissions_ajout_rapport() {
        let enforcer = Enforcer::load().unwrap();

        for (acteur, cible) in generer_cas_test() {
            let rapport = MedicalReport {
                id: ReportID::new(),
                title: "Rapport de test".to_string(),
                author: acteur.id,
                patient: cible.id,
                content: "Contenu du rapport".to_string(),
            };

            let contexte = enforcer.with_subject(&acteur);
            let resultat = contexte.add_report(&cible, &rapport);

            match acteur.role {
                Role::Admin => {
                    assert!(
                        resultat.is_ok(),
                        "L'administrateur devrait pouvoir ajouter un rapport pour n'importe quel utilisateur"
                    );
                }
                Role::Doctor => {
                    if cible.medical_folder.is_some() {
                        assert!(
                            resultat.is_ok(),
                            "Un médecin devrait pouvoir ajouter un rapport pour un patient avec un dossier médical"
                        );
                    } else {
                        assert!(
                            resultat.is_err(),
                            "Un médecin ne devrait pas pouvoir ajouter un rapport pour un patient sans dossier médical"
                        );
                    }
                }
                _ => {
                    assert!(
                        resultat.is_err(),
                        "Seuls les administrateurs et les médecins devraient pouvoir ajouter des rapports"
                    );
                }
            }
        }
    }

    /// Teste l'existence du dossier médical avant d'ajouter un rapport.
    #[test]
    fn test_existence_dossier_pour_rapport() {
        let enforcer = Enforcer::load().unwrap();

        for (acteur, cible) in generer_cas_test() {
            let rapport = MedicalReport {
                id: ReportID::new(),
                title: "Rapport de test".to_string(),
                author: acteur.id,
                patient: cible.id,
                content: "Contenu du rapport".to_string(),
            };

            let contexte = enforcer.with_subject(&acteur);

            let resultat = contexte.add_report(&cible, &rapport);

            if acteur.role == Role::Doctor {
                if cible.medical_folder.is_some() {
                    assert!(
                        resultat.is_ok(),
                        "Le médecin devrait pouvoir ajouter un rapport si le dossier du patient existe"
                    );
                } else {
                    assert!(
                        resultat.is_err(),
                        "Le médecin ne devrait pas pouvoir ajouter un rapport si le dossier du patient n'existe pas"
                    );
                }
            }
        }
    }

    /// Teste les permissions pour lire les rapports médicaux.
    #[test]
    fn test_permissions_lecture_rapport() {
        let enforcer = Enforcer::load().unwrap();
        for (acteur, cible) in generer_cas_test() {
            let rapport = MedicalReport {
                id: ReportID::new(),
                title: "Rapport médical".to_string(),
                author: cible.id,
                patient: cible.id,
                content: "Contenu confidentiel".to_string(),
            };

            let contexte = enforcer.with_subject(&acteur);
            let resultat = contexte.read_report(&rapport, &cible);

            if acteur.role == Role::Admin
                || acteur.id == rapport.author
                || (acteur.role == Role::Doctor
                    && cible
                        .medical_folder
                        .as_ref()
                        .map_or(false, |folder| folder.doctors.contains(&acteur.id)))
            {
                assert!(resultat.is_ok(), "L'accès au rapport devrait être autorisé.");
            } else {
                assert!(resultat.is_err(), "L'accès au rapport devrait être refusé.");
            }
        }
    }

    /// Teste les permissions pour mettre à jour les rapports médicaux.
    #[test]
    fn test_permissions_mise_a_jour_rapport() {
        let enforcer = Enforcer::load().unwrap();

        for (acteur, _) in generer_cas_test() {
            let rapport = MedicalReport {
                id: ReportID::new(),
                title: "Rapport de test".to_string(),
                author: acteur.id,
                patient: acteur.id,
                content: "Contenu du rapport".to_string(),
            };

            let contexte = enforcer.with_subject(&acteur);
            let resultat = contexte.update_report(&rapport);

            match acteur.role {
                Role::Admin => {
                    assert!(
                        resultat.is_ok(),
                        "L'administrateur devrait pouvoir mettre à jour n'importe quel rapport"
                    );
                }
                _ => {
                    if acteur.id == rapport.author {
                        assert!(
                            resultat.is_ok(),
                            "Un utilisateur devrait pouvoir mettre à jour ses propres rapports"
                        );
                    } else {
                        assert!(
                            resultat.is_err(),
                            "Un utilisateur ne devrait pas pouvoir mettre à jour les rapports des autres"
                        );
                    }
                }
            }
        }
    }

    /// Teste les permissions pour mettre à jour le rôle d'un utilisateur.
    #[test]
    fn test_permissions_mise_a_jour_role() {
        let enforcer = Enforcer::load().unwrap();

        for acteur in Role::iter().map(|role| creer_utilisateur(role, false)) {
            let contexte = enforcer.with_subject(&acteur);

            // Tester la mise à jour des rôles pour tous les utilisateurs cibles
            for cible in Role::iter().map(|role| creer_utilisateur(role, false)) {
                let resultats = Role::iter().map(|role| contexte.update_role(&cible, role));

                // Les administrateurs peuvent toujours mettre à jour les rôles
                if acteur.role == Role::Admin {
                    assert!(
                        resultats.clone().all(|res| res.is_ok()),
                        "L'administrateur devrait pouvoir modifier les rôles de n'importe quel utilisateur"
                    );
                    continue;
                }

                // Tous les autres cas devraient être refusés
                assert!(
                    resultats.clone().all(|res| res.is_err()),
                    "Accès inattendu autorisé : {:?} modifiant le rôle de {:?}",
                    acteur.role,
                    cible.role
                );
            }
        }
    }

    #[test]
    fn test_permissions_gestion_medecins() {
        let enforcer = Enforcer::load().unwrap();
        for (acteur, mut cible) in generer_cas_test() {
            let medecin = creer_utilisateur(Role::Doctor, false);
            if let Some(folder) = &mut cible.medical_folder {
                let contexte = enforcer.with_subject(&acteur);
                let ajout = contexte.add_doctor(&cible, &medecin);
                let suppression = contexte.remove_doctor(&cible, &medecin);

                if acteur.role == Role::Admin || acteur.id == cible.id {
                    assert!(ajout.is_ok() && suppression.is_ok(), "Seul admin ou propriétaire peut gérer médecins.");
                } else {
                    assert!(ajout.is_err() && suppression.is_err(), "Autres ne devraient pas gérer médecins.");
                }
            }
        }
    }

    /// Teste les fonctions utilitaires liées au dossier médical.
    #[test]
    fn test_utilitaires_dossier_medical() {
        let mut dossier = MedicalFolder::new(PersonalData {
            avs_number: AVSNumber::try_from("756.1234.5678.97").unwrap(),
            blood_type: BloodType::A,
        });

        let id_medecin = UserID::new();

        // Vérifie que le dossier est vide initialement
        assert!(!dossier.doctors.contains(&id_medecin), "Le dossier médical ne devrait pas contenir de médecins initialement");

        // Ajoute un médecin au dossier
        dossier.doctors.insert(id_medecin);
        assert!(dossier.doctors.contains(&id_medecin), "Le dossier médical devrait contenir le médecin après l'ajout");

        // Supprime le médecin du dossier
        dossier.doctors.remove(&id_medecin);
        assert!(!dossier.doctors.contains(&id_medecin), "Le dossier médical ne devrait plus contenir le médecin après la suppression");
    }


    #[test]
    fn test_limitation_acces_medecin() {
        let enforcer = Enforcer::load().unwrap();

        for (acteur, cible) in generer_cas_test() {
            let contexte = enforcer.with_subject(&acteur);

            if acteur.role == Role::Doctor {
                let resultat = contexte.read_data(&cible);

                if cible
                    .medical_folder
                    .as_ref()
                    .map_or(false, |folder| folder.doctors.contains(&acteur.id))
                {
                    assert!(
                        resultat.is_ok(),
                        "Le médecin devrait pouvoir accéder aux données de son patient"
                    );
                } else {
                    assert!(
                        resultat.is_err(),
                        "Le médecin ne devrait pas pouvoir accéder aux données d'un patient qui n'est pas le sien"
                    );
                }
            }
        }
    }

    

        /// Teste les permissions pour créer un dossier médical personnel.
        #[test]
        fn test_permissions_creation_dossier() {
            let enforcer = Enforcer::load().unwrap();
    
            for (acteur, cible) in generer_cas_test() {
                let contexte = enforcer.with_subject(&acteur);
                let resultat = contexte.enforce(&cible, "create-folder");
    
                match acteur.role {
                    Role::Admin => {
                        assert!(
                            resultat.is_ok(),
                            "L'administrateur devrait pouvoir créer un dossier pour n'importe quel utilisateur"
                        );
                    }
                    Role::Patient => {
                        if acteur.id == cible.id {
                            assert!(
                                resultat.is_ok(),
                                "Un utilisateur devrait pouvoir créer son propre dossier médical"
                            );
                        } else {
                            assert!(
                                resultat.is_err(),
                                "Un utilisateur ne devrait pas pouvoir créer un dossier pour quelqu'un d'autre"
                            );
                        }
                    }
                    _ => {
                        assert!(
                            resultat.is_err(),
                            "Seuls les patients et les administrateurs devraient pouvoir créer un dossier médical"
                        );
                    }
                }
            }
        }    
}
 

    
    

