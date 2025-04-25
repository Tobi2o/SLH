//! Gère l'intégration de WebAuthn pour l'enregistrement, l'authentification, et la récupération.
//! Fournit des fonctions pour démarrer et compléter les processus d'enregistrement et d'authentification.
//! Inclut également des mécanismes pour la gestion sécurisée des passkeys et des tokens de récupération.

use std::collections::HashMap;
use anyhow::{Result, Context};
use webauthn_rs::prelude::*;
use once_cell::sync::Lazy;
use url::Url;
use tokio::sync::RwLock;
use serde_json::{json, Value};
use uuid::Uuid;
use crate::backend::handlers_unauth::{REGISTRATION_STATES, AUTHENTICATION_STATES, TimedStoredState};
use  base64;
use crate::utils::input::valid_email;
use crate::backend::handlers_unauth::register_begin;
use axum::Json;


// Initialisation globale de WebAuthn
static WEBAUTHN: Lazy<Webauthn> = Lazy::new(|| {
    let rp_id = "localhost";
    let rp_origin = Url::parse("http://localhost:8080").expect("Invalid RP origin URL");

    WebauthnBuilder::new(rp_id, &rp_origin)
        .expect("Failed to initialize WebAuthn")
        .build()
        .expect("Failed to build WebAuthn instance")
});

// Store sécurisé pour les passkeys
pub static CREDENTIAL_STORE: Lazy<RwLock<HashMap<String, Passkey>>> = Lazy::new(Default::default);

// Structure pour stocker l'état d'enregistrement
pub(crate) struct StoredRegistrationState {
    pub registration_state: PasskeyRegistration,
    pub challenge: String,
}

/// Démarrer l'enregistrement WebAuthn
pub async fn begin_registration(
    user_email: &str,
    user_display_name: &str,
) -> Result<(Value, PasskeyRegistration)> {
    let user_id = Uuid::new_v4();

    // Generate registration challenge
    let (challenge_response, registration_state) = WEBAUTHN
        .start_passkey_registration(user_id, user_email, user_display_name, None)
        .context("Failed to start passkey registration")?;

    // Store registration state
    let encoded_challenge = base64::encode(challenge_response.public_key.challenge.to_vec());

    let mut states = REGISTRATION_STATES.write().await;
    states.insert(
        user_email.to_string(),
        StoredRegistrationState {
            registration_state: registration_state.clone(),
            challenge: encoded_challenge.clone(),
        },
    );

    // Return client registration options
    Ok((
        json!({
            "rp": challenge_response.public_key.rp,
            "user": {
                "id": challenge_response.public_key.user.id,
                "name": challenge_response.public_key.user.name,
                "displayName": challenge_response.public_key.user.display_name,
            },
            "challenge": encoded_challenge, // Encoded challenge
            "pubKeyCredParams": challenge_response.public_key.pub_key_cred_params,
            "timeout": challenge_response.public_key.timeout,
            "authenticatorSelection": challenge_response.public_key.authenticator_selection,
            "attestation": challenge_response.public_key.attestation,
        }),
        registration_state,
    ))
}


/// Compléter l'enregistrement WebAuthn
pub async fn complete_registration(
    user_email: &str,
    response: &RegisterPublicKeyCredential,
    stored_state: &StoredRegistrationState,
) -> Result<()> {
    let passkey = WEBAUTHN
        .finish_passkey_registration(response, &stored_state.registration_state)
        .context("Failed to complete passkey registration")?;

    // Save passkey
    let mut store = CREDENTIAL_STORE.write().await;
    store.insert(user_email.to_string(), passkey);

    Ok(())
}

/// Démarrer l'authentification WebAuthn
pub async fn begin_authentication(user_email: &str) -> Result<(Value, PasskeyAuthentication)> {
    let store = CREDENTIAL_STORE.read().await;
    let passkey = store.get(user_email)
        .ok_or_else(|| anyhow::anyhow!("No passkey found for user"))?;

    // Generate authentication challenge
    let (challenge_response, auth_state) = WEBAUTHN
        .start_passkey_authentication(&[passkey.clone()])
        .context("Failed to start authentication")?;

    // Store authentication state
    let encoded_challenge = base64::encode(challenge_response.public_key.challenge.to_vec());
    let mut states = AUTHENTICATION_STATES.write().await;
    states.insert(
        user_email.to_string(),
        TimedStoredState::new(auth_state.clone(), encoded_challenge.clone()),
    );

    // Return client authentication options
    Ok((
        json!({
            "challenge": encoded_challenge, // Encoded challenge
            "timeout": challenge_response.public_key.timeout,
            "rpId": challenge_response.public_key.rp_id,
            "allowCredentials": challenge_response.public_key.allow_credentials,
        }),
        auth_state,
    ))
}

/// Compléter l'authentification WebAuthn
pub async fn complete_authentication(
    response: &PublicKeyCredential,
    state: &PasskeyAuthentication,
    server_challenge: &str,
) -> Result<()> {
    // Validate response against the challenge
    WEBAUTHN
        .finish_passkey_authentication(response, state)
        .context("Failed to complete authentication")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use serde_json::json;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_valid_email() {
        assert!(valid_email("test@example.com"));
        assert!(!valid_email("invalid-email"));
    }


    #[tokio::test]
    async fn test_begin_registration_success() {
        // Setup: User information
        let email = "test@example.com";
        let display_name = "Test User";
    
        // Call `begin_registration`
        let result = begin_registration(email, display_name).await;
    
        // Assertions
        assert!(result.is_ok());
        let (public_key_options, _reg_state) = result.unwrap();
        assert!(public_key_options["challenge"].is_string());
        assert!(public_key_options["rp"].is_object());
        assert!(public_key_options["user"].is_object());
    }
}

    // pas eu le temps de finir les tests ils sont assez longs à écrire et complexes


