use actix_session::Session;
use actix_web::{web, HttpResponse, Responder};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use derive_more::Display;
use rand::{distributions::Alphanumeric, rngs::OsRng, Rng};
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};

use crate::state::AppState;

const ADMIN_SESSION_KEY: &str = "admin_user_id";

#[derive(Debug, Display)]
pub enum AuthError {
    #[display("database error: {0}")]
    Database(String),
    #[display("password hashing error")]
    Hash,
    #[display("session error: {0}")]
    Session(String),
}

impl std::error::Error for AuthError {}

fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AuthError::Hash)
}

async fn store_user(
    pool: &SqlitePool,
    username: &str,
    password_hash: &str,
) -> Result<(), AuthError> {
    sqlx::query("INSERT INTO users (username, password_hash) VALUES (?1, ?2)")
        .bind(username)
        .bind(password_hash)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| AuthError::Database(e.to_string()))
}

pub async fn ensure_initial_admin(pool: &SqlitePool) -> Result<(), AuthError> {
    let row = sqlx::query("SELECT COUNT(*) as count FROM users")
        .fetch_one(pool)
        .await
        .map_err(|e| AuthError::Database(e.to_string()))?;
    let count: i64 = row.try_get("count").unwrap_or(0);

    if count > 0 {
        return Ok(());
    }

    let username = std::env::var("LLMSERVER_ADMIN_USERNAME").unwrap_or_else(|_| "admin".to_owned());
    let password = std::env::var("LLMSERVER_ADMIN_PASSWORD").unwrap_or_else(|_| {
        rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect::<String>()
    });

    let password_hash = hash_password(&password)?;
    store_user(pool, &username, &password_hash).await?;

    println!(
        "Created initial administrator account. Username: {username}. Generated password: {password}"
    );

    Ok(())
}

async fn authenticate(
    pool: &SqlitePool,
    username: &str,
    password: &str,
) -> Result<Option<i64>, AuthError> {
    let record = sqlx::query("SELECT id, password_hash FROM users WHERE username = ?1")
        .bind(username)
        .fetch_optional(pool)
        .await
        .map_err(|e| AuthError::Database(e.to_string()))?;

    let Some(record) = record else {
        return Ok(None);
    };

    let password_hash: String = record
        .try_get("password_hash")
        .map_err(|_| AuthError::Hash)?;
    let user_id: i64 = record.try_get("id").map_err(|_| AuthError::Hash)?;
    let parsed_hash = PasswordHash::new(&password_hash).map_err(|_| AuthError::Hash)?;
    if Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
    {
        Ok(Some(user_id))
    } else {
        Ok(None)
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub username: String,
}

pub async fn login(
    state: web::Data<AppState>,
    session: Session,
    payload: web::Json<LoginRequest>,
) -> Result<impl Responder, actix_web::Error> {
    match authenticate(&state.pool, &payload.username, &payload.password).await {
        Ok(Some(user_id)) => {
            session
                .insert(ADMIN_SESSION_KEY, user_id)
                .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
            Ok(HttpResponse::Ok().json(LoginResponse {
                username: payload.username.clone(),
            }))
        }
        Ok(None) => Ok(HttpResponse::Unauthorized().finish()),
        Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
    }
}

pub async fn logout(session: Session) -> Result<impl Responder, actix_web::Error> {
    session.remove(ADMIN_SESSION_KEY);
    Ok(HttpResponse::Ok().finish())
}

pub fn is_authenticated(session: &Session) -> Result<bool, actix_web::Error> {
    Ok(session.get::<i64>(ADMIN_SESSION_KEY)?.is_some())
}

pub fn require_admin(session: &Session) -> Result<i64, actix_web::Error> {
    session
        .get::<i64>(ADMIN_SESSION_KEY)?
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("authentication required"))
}

#[derive(Debug, Deserialize)]
pub struct CreateAdminRequest {
    pub username: String,
    pub password: String,
}

pub async fn create_admin(
    state: web::Data<AppState>,
    session: Session,
    payload: web::Json<CreateAdminRequest>,
) -> Result<impl Responder, actix_web::Error> {
    require_admin(&session)?;

    let password_hash = hash_password(&payload.password).map_err(|e| {
        actix_web::error::ErrorInternalServerError(format!("password hashing error: {e}"))
    })?;

    match store_user(&state.pool, &payload.username, &password_hash).await {
        Ok(_) => Ok(HttpResponse::Created().finish()),
        Err(AuthError::Database(e)) if e.contains("UNIQUE") => {
            Ok(HttpResponse::Conflict().body("username already exists"))
        }
        Err(e) => Ok(HttpResponse::InternalServerError().body(e.to_string())),
    }
}

#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub username: String,
}

pub async fn current_admin(
    state: web::Data<AppState>,
    session: Session,
) -> Result<impl Responder, actix_web::Error> {
    let user_id = require_admin(&session)?;
    let row = sqlx::query("SELECT username FROM users WHERE id = ?1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let username: String = row
        .try_get("username")
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    Ok(HttpResponse::Ok().json(SessionInfo { username }))
}
