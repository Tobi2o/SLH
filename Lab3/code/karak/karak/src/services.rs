//! API d'accès au dossier, et point d'entrée unique pour le contrôle d'accès.
//!
use crate::authorization::{AccessDenied, Context, Enforcer};
use crate::db::{DBError, Database};
use crate::models::{MedicalFolder, MedicalReport, PersonalData, ReportID, Role, UserData, UserID};
use crate::utils::input_validation::{password_input_validation, Username};
use crate::utils::password_utils::{hash, verify};
use log::info;
use thiserror::Error;

pub struct Service {
    user: Option<UserID>,
    db: Database,
    enforcer: Enforcer,
}

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error(transparent)]
    AccessDenied(#[from] AccessDenied),

    #[error("Utilisateur déja inscrit")]
    UserAlreadyExists,

    #[error(transparent)]
    DBError(#[from] DBError),

    #[error("Pas de dossier pour ce patient")]
    NotAPatient,

    #[error("Rapport inexistant")]
    NoSuchReport,
}

#[derive(Debug, Error)]
pub enum LoginError {
    #[error("Mauvais mot de passe ou utilisateur inconnu")]
    InvalidCredentials,
}

impl Service {
    pub fn new(db: Database, enforcer: Enforcer) -> Self {
        Self {
            db,
            user: None,
            enforcer,
        }
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        self.db.save()
    }

    /// Enregistre un nouvel utilisateur (Patient ou Docteur) dans la base de données.
    pub fn register(&mut self, username: Username) -> Result<UserID, ServiceError> {
        let password = password_input_validation(username.as_ref());
        let password = hash(&password);

        if self.db.lookup_username(&username).is_some() {
            return Err(ServiceError::UserAlreadyExists);
        }

        let new_uid = UserID::new();
        let new_user = UserData {
            id: new_uid,
            role: Role::Patient,
            username,
            password,
            medical_folder: None,
        };

        info!(
            "Compte créé avec succès pour l'utilisateur {}",
            &new_user.username
        );
        self.db.store_user(new_user);
        Ok(new_uid)
    }

    /// Obtient les données courantes de l'utilisateur connecté
    fn get_subject(&self) -> Option<&UserData> {
        self.db.get_user(self.user?).ok()
    }

    /// Crée un contexte d'autorisation ayant l'utilisateur connecté comme sujet
    fn enforce(&self) -> Result<Context<'_>, ServiceError> {
        let subject = self
            .get_subject()
            .ok_or(ServiceError::AccessDenied(AccessDenied))?;

        Ok(self.enforcer.with_subject(subject))
    }

    /// Vérifie si le mot de passe est correct, et si oui, enregistre
    /// L'utilisateur comme utilisateur courant.
    pub fn login(&mut self, username: &Username, password: &str) -> Result<UserID, LoginError> {
        let user = self.db.lookup_username(username);
        let hash = user.as_ref().map(|u| &u.password);
        if !verify(password, hash) {
            return Err(LoginError::InvalidCredentials);
        }
        let user = user.unwrap();
        self.user = Some(user.id);
        Ok(user.id)
    }

    /// Ferme la session
    pub fn logout(&mut self) {
        self.user = None
    }

    /// Cherche un ID utilisateur par nom d'utilisateur
    pub fn lookup_user(&self, username: &Username) -> Option<UserID> {
        Some(self.db.lookup_username(username)?.id)
    }

    /// Change le role d'un utilisateur
    pub fn update_role(&mut self, user_id: UserID, new_role: Role) -> Result<(), ServiceError> {
        // Récupérer les données de l'utilisateur cible
        let target = self.db.get_user(user_id)?;

        // Vérifier si l'utilisateur connecté est autorisé à changer le rôle
        self.enforce()?.update_role(target, new_role)?;

        // Modifier le rôle dans la base de données
        let user = self.db.get_user_mut(user_id)?;
        user.role = new_role;
        Ok(())
    }

    /// Récupère les données d'un utilisateur
    pub fn get_data(&self, user_id: UserID) -> Result<&UserData, ServiceError> {
        let target = self.db.get_user(user_id)?;
        self.enforce()?.read_data(target)?;

        // Retourner les données si l'accès est autorisé
        Ok(target)
    }

    /// Change les données personnelles d'un utilisateur. Si le dossier médical
    /// n'existait pas, il est créé pour l'occasion.
    pub fn update_data(
        &mut self,
        user_id: UserID,
        personal_data: PersonalData,
    ) -> Result<(), ServiceError> {
        let target = self.db.get_user(user_id)?;
        self.enforce()?.update_data(target)?;

        let folder = &mut self.db.get_user_mut(user_id)?.medical_folder;

        if let Some(folder) = folder {
            folder.personal_data = personal_data;
        } else {
            *folder = Some(MedicalFolder::new(personal_data));
        }
        Ok(())
    }

    /// Efface toutes les données médicales relatives à un patient
    /// (S'il est également médecin, son rôle de médecin n'est pas
    /// affecté)
    pub fn delete_data(&mut self, patient: UserID) -> Result<(), ServiceError> {
        let target = self.db.get_user(patient)?;
        self.enforce()?.delete_data(target)?;

        self.db.get_user_mut(patient)?.medical_folder = None;
        self.db.remove_reports(patient);
        Ok(())
    }

    /// Ecrire un nouveau rapport médical
    pub fn add_report(
        &mut self,
        author: UserID,
        patient: UserID,
        title: String,
        content: String,
    ) -> Result<(), ServiceError> {
        let report = MedicalReport {
            id: ReportID::new(),
            title,
            author,
            patient,
            content,
        };

        let patient_data = self.db.get_user(patient)?;
        self.enforce()?.add_report(patient_data, &report)?;

        self.db.store_report(report);
        Ok(())
    }

    pub fn list_reports(&self, user_id: UserID) -> impl Iterator<Item = &MedicalReport> + '_ {
        self.enforce().ok().into_iter().flat_map(move |ctx| {
            self.db
                .list_reports()
                .filter(move |report| report.patient == user_id)
                .filter(move |report| {
                    let Ok(patient) = self.db.get_user(report.patient) else {
                        return false;
                    };

                    ctx.read_report(report, patient).is_ok()
                })
        })
    }

    pub fn list_patients(&self) -> impl Iterator<Item = &UserData> + '_ {
        self.user
            .iter()
            .flat_map(|&u| self.db.get_patients(u))
            .filter_map(|id| self.db.get_user(id).ok())
    }

    pub fn add_doctor(
        &mut self,
        patient_id: UserID,
        doctor_id: UserID,
    ) -> Result<(), ServiceError> {
        let doctor = self.db.get_user(doctor_id)?;
        let patient = self.db.get_user(patient_id)?;
        self.enforce()?.add_doctor(patient, doctor)?;

        // Ajouter le médecin au dossier médical du patient
        let patient = self.db.get_user_mut(patient_id)?;
        patient
            .medical_folder
            .as_mut()
            .map(|f| f.doctors.insert(doctor_id));
        Ok(())
    }

    pub fn remove_doctor(
        &mut self,
        patient_id: UserID,
        doctor_id: UserID,
    ) -> Result<(), ServiceError> {
        let doctor = self.db.get_user(doctor_id)?;
        let patient = self.db.get_user(patient_id)?;

        self.enforce()?.remove_doctor(patient, doctor)?;

        // Retirer le médecin du dossier médical du patient
        let patient = self.db.get_user_mut(patient_id)?;
        patient
            .medical_folder
            .as_mut()
            .map(|f| f.doctors.remove(&doctor_id));
        Ok(())
    }

    pub fn update_report(
        &mut self,
        report_id: ReportID,
        content: String,
    ) -> Result<(), ServiceError> {
        let report = self
            .db
            .get_report(report_id)
            .ok_or(ServiceError::NoSuchReport)?;

        self.enforce()?.update_report(report)?;
        *self.db.get_report_data_mut(report_id).unwrap() = content;
        Ok(())
    }
}
