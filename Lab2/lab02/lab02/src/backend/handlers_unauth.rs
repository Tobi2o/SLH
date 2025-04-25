//! Gestion des routes accessibles sans authentification.
//! Contient les handlers pour les pages publiques, l'inscription, la connexion,
//! la récupération de compte et la validation d'utilisateur.

use axum::{
    extract::{Path, Json, Query},
    response::{Redirect, IntoResponse, Html},
    http::StatusCode,
};

use once_cell::sync::Lazy;
use serde_json::json;
use std::collections::HashMap;
use tokio::sync::RwLock;
use webauthn_rs::prelude::{PasskeyAuthentication, PublicKeyCredential, RegisterPublicKeyCredential};
use crate::HBS;
use crate::database::{user, token};
use crate::utils::webauthn::{begin_registration, complete_registration, begin_authentication, complete_authentication, StoredRegistrationState, CREDENTIAL_STORE};
use crate::utils::input::{valid_email, valid_name, valid_id, valid_bool};
use crate::email::send_mail;
use log::error;
/// Structure pour gérer un état temporaire avec un challenge
pub struct TimedStoredState<T> {
    state: T,
    server_challenge: String,
}
impl<T> TimedStoredState<T> {
    /// Constructor for TimedStoredState
    pub fn new(state: T, server_challenge: String) -> Self {
        TimedStoredState {
            state,
            server_challenge,
        }
    }
}
/// Stockage des états d'enregistrement et d'authentification
pub(crate) static REGISTRATION_STATES: Lazy<RwLock<HashMap<String, StoredRegistrationState>>> =
    Lazy::new(Default::default);
pub static AUTHENTICATION_STATES: Lazy<RwLock<HashMap<String, TimedStoredState<PasskeyAuthentication>>>> = Lazy::new(Default::default);

/// Début du processus d'enregistrement WebAuthn
pub async fn register_begin(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Json<serde_json::Value>> {
     // Extract the user email from the JSON payload
   
     let user_email = payload
     .get("email")
     .and_then(|value| value.as_str())
     .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    // Validate the email format
    if !valid_email(user_email) {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format").into());
    }

    // Check if the user already exists and if reset mode is enabled
    let reset_flag = payload.get("reset_mode");

    if user::exists(user_email).unwrap() && !valid_bool(reset_flag) {
        return Err((StatusCode::BAD_REQUEST, "Action not permitted").into());
    }

    // Start the WebAuthn registration process
    let (public_key_options, reg_state) = begin_registration(user_email, user_email)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to begin registration: {}", error)))?;

    // Generate a unique state identifier
    let unique_state_id = uuid::Uuid::new_v4().to_string();

    // Store the registration state
    let mut reg_state_store = REGISTRATION_STATES.write().await;
    reg_state_store.insert(unique_state_id.clone(), StoredRegistrationState {
        registration_state: reg_state,
        challenge: public_key_options["challenge"].as_str().unwrap().to_string(),
    });


    // Return the JSON response with public key options and the unique state ID
    Ok(Json(json!({
        "publicKey": public_key_options,
        "state_id": unique_state_id,
    })))
   
}


/// Fin du processus d'enregistrement WebAuthn
pub async fn register_complete(Json(payload): Json<serde_json::Value>) -> axum::response::Result<StatusCode> {
    // Extract and validate the user's email from the JSON payload


    let user_email = payload
        .get("email")
        .and_then(|value| value.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;

    if !valid_email(user_email) {
        return Err((StatusCode::BAD_REQUEST, "Invalid email format").into());
    }

    // Extract and validate the user's first name
    let user_first_name = payload
        .get("first_name")
        .and_then(|value| value.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "First name is required"))?;
    if !valid_name(user_first_name) {
        return Err((StatusCode::BAD_REQUEST, "Invalid first name").into());
    }

    // Extract and validate the user's last name
    let user_last_name = payload
        .get("last_name")
        .and_then(|value| value.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Last name is required"))?;
    if !valid_name(user_last_name) {
        return Err((StatusCode::BAD_REQUEST, "Invalid last name").into());
    }

    // Extract and validate the registration state ID
    let reg_state_id = payload
        .get("state_id")
        .and_then(|value| value.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "State ID is required"))?;
    if !valid_id(reg_state_id) {
        return Err((StatusCode::BAD_REQUEST, "Invalid state ID").into());
    }

    // Retrieve and remove the stored registration state
    let mut reg_state_store = REGISTRATION_STATES.write().await;
    let stored_reg_state = reg_state_store
        .remove(reg_state_id)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid state ID"))?;

    // Extract and validate the registration response
    let reg_response: RegisterPublicKeyCredential = serde_json::from_value(payload.get("response").unwrap().clone())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid response format"))?;
    log::info!("User email: {}", user_email);
    // Complete the WebAuthn registration process
    complete_registration(
        user_email,
        &reg_response,
        &stored_reg_state,
    )
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to complete registration"))?;

    // Create a new user in the database
    user::create(user_email, user_first_name, user_last_name)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to store user details"))?;

    // Generate a verification token and send a verification email
    if let Ok(verification_token) = token::generate(user_email) {
        if send_mail(
            user_email,
            "Link your account",
            &format!(
                "Hello {}! Please link your account by following this URL: http://localhost:8080/validate/{}",
                user_email, verification_token
            ),
        )
            .is_err()
        {
            error!("Failed to send verification email to {}", user_email);
        }
    }

    // Associate the passkey with the user
    let user_passkey = CREDENTIAL_STORE.read().await.get(user_email).unwrap().clone();
    user::set_passkey(user_email, user_passkey).map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to set passkey"))?;

    // Return OK status
    Ok(StatusCode::OK)
}




/// Début du processus d'authentification WebAuthn
pub async fn login_begin(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Json<serde_json::Value>> {
   // Extract and validate the user's email from the JSON payload
   let user_email = payload
   .get("email")
   .and_then(|value| value.as_str())
   .ok_or((StatusCode::BAD_REQUEST, "Email is required"))?;
    if !valid_email(user_email) {
    return Err((StatusCode::BAD_REQUEST, "Invalid email format").into());
    }

    // Start the WebAuthn authentication process
    let (auth_challenge_response, auth_state) = begin_authentication(user_email)
    .await
    .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to initiate authentication"))?;

    // Generate a unique state identifier
    let auth_state_id = uuid::Uuid::new_v4().to_string();

    // Store the authentication state
    AUTHENTICATION_STATES
    .write()
    .await
    .insert(auth_state_id.clone(), TimedStoredState {
        state: auth_state,
        server_challenge: auth_challenge_response["challenge"].as_str().unwrap().to_string(),
    });

    // Return the JSON response with the public key and state ID
    Ok(Json(json!({
    "publicKey": auth_challenge_response,
    "state_id": auth_state_id,
    })))
}

/// Fin du processus d'authentification WebAuthn
pub async fn login_complete(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Redirect> {
    // Extract and validate the response and state identifier from the input payload
    let auth_response = payload
        .get("response")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Authentication response is required"))?;
    let auth_state_id = payload
        .get("state_id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "State ID is required"))?;

    // Deserialize and validate the authentication response format
    let auth_response: PublicKeyCredential = serde_json::from_value(auth_response.clone())
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid authentication response format"))?;

    // Validate the state ID format
    if !valid_id(auth_state_id) {
        return Err((StatusCode::BAD_REQUEST, "Invalid state ID format").into());
    }

    // Retrieve and validate the stored authentication state using the state ID
    let mut authentication_states = AUTHENTICATION_STATES.write().await;
    let stored_auth_state = authentication_states
        .remove(auth_state_id)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid or expired authentication state ID"))?;

    // Complete the WebAuthn authentication process
    complete_authentication(
        &auth_response,
        &stored_auth_state.state,
        &stored_auth_state.server_challenge,
    )
    .await
    .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to complete authentication: {}", error)))?;

    // Redirect the user to the home page upon successful authentication
    Ok(Redirect::to("/home"))
}

/// Gère la déconnexion de l'utilisateur
pub async fn logout() -> impl IntoResponse {
    Redirect::to("/")
}

/// Valide un compte utilisateur via un token
pub async fn validate_account(Path(token): Path<String>) -> impl IntoResponse {
    match token::consume(&token) {
        Ok(email) => match user::verify(&email) {
            Ok(_) => Redirect::to("/login?validated=true"),
            Err(_) => Redirect::to("/register?error=validation_failed"),
        },
        Err(_) => Redirect::to("/register?error=invalid_token"),
    }
}

/// Envoie un email de récupération de compte à l'utilisateur
pub async fn recover_account(Json(payload): Json<serde_json::Value>) -> axum::response::Result<Html<String>> {
    let mut response_data = HashMap::new();

    // Extract and validate the user's email from the input payload
    let user_email = payload
        .get("email")
        .and_then(|value| value.as_str())
        .ok_or((StatusCode::BAD_REQUEST, "Email address is required"))?;

    // Generate a unique recovery token for the user
    let recovery_token = token::generate(user_email)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate recovery token"))?;

    // Construct the recovery URL using the generated token
    let recovery_link = format!("http://localhost:8080/recover/{}", recovery_token);

    // Attempt to send the recovery email to the user
    let email_send_result = send_mail(
        user_email,
        "Account Recovery",
        &format!("Please click the following link to recover your account: {}", recovery_link),
    );

    // Insert a success message into the response data
    response_data.insert("message", "Recovery email sent successfully.");

    // Check if sending the email failed
    if email_send_result.is_err() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Failed to send recovery email").into());
    }

    // Render the recovery page and return the response
    HBS.render("recover", &response_data)
        .map(Html)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error while rendering the page").into())
}

/// Gère la réinitialisation du compte utilisateur via un token de récupération
pub async fn reset_account(Path(token): Path<String>) -> Html<String> {
    match token::consume(&token) {
        Ok(email) => {
            let redirect_url = format!("/register?reset_mode=true&email={}&success=true", email);
            Html(format!("<meta http-equiv='refresh' content='0;url={}'/>", redirect_url))
        }
        Err(_) => {
            let redirect_url = "/register?error=recovery_failed";
            Html(format!("<meta http-equiv='refresh' content='0;url={}'/>", redirect_url))
        }
    }
}

/// --- Affichage des pages ---
///
/// Affiche la page d'accueil
pub async fn index(session: tower_sessions::Session) -> impl IntoResponse {
    let is_logged_in = session.get::<String>("email").is_ok();
    let mut data = HashMap::new();
    data.insert("logged_in", is_logged_in);

    HBS.render("index", &data)
        .map(Html)
        .unwrap_or_else(|_| Html("Internal Server Error".to_string()))
}

/// Affiche la page de connexion
pub async fn login_page() -> impl IntoResponse {
    Html(include_str!("../../templates/login.hbs"))
}

/// Affiche la page d'inscription avec des messages contextuels si présents
pub async fn register_page(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let mut context = HashMap::new();
    if let Some(success) = params.get("success") {
        if success == "true" {
            context.insert("success_message", "Account recovery successful. Please reset your passkey.");
        }
    }
    if let Some(error) = params.get("error") {
        if error == "recovery_failed" {
            context.insert("error_message", "Invalid or expired recovery link. Please try again.");
        }
    }

    HBS.render("register", &context)
        .map(Html)
        .unwrap_or_else(|_| Html("<h1>Internal Server Error</h1>".to_string()))
}

/// Affiche la page de récupération de compte
pub async fn recover_page() -> impl IntoResponse {
    Html(include_str!("../../templates/recover.hbs"))
}
