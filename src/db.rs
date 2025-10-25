use std::{fmt, path::Path, sync::Arc, time::Duration};

use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use chrono::{DateTime, Utc};
use r2d2::{Pool, PooledConnection};
use r2d2_sqlite::SqliteConnectionManager;
use rand::{distributions::Alphanumeric, Rng};
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::crypto::{CryptoError, SecretCipher};

#[derive(Clone)]
pub struct Database {
    pool: Arc<Pool<SqliteConnectionManager>>,
    cipher: SecretCipher,
}

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: i64,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct ApiKeyRecord {
    pub id: i64,
    pub name: String,
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ModelDownloadRecord {
    pub id: i64,
    pub repo_id: String,
    pub revision: String,
    pub local_path: String,
    pub model_type: String,
    pub size_bytes: i64,
    pub downloaded_at: DateTime<Utc>,
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),
    #[error("argon2 error: {0}")]
    Argon2(#[from] argon2::Error),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("blocking task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl Database {
    pub fn initialise(path: &Path, cipher: SecretCipher) -> Result<Self, DatabaseError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let manager = SqliteConnectionManager::file(path).with_flags(
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_FULL_MUTEX,
        );
        let pool = Pool::builder()
            .max_size(16)
            .connection_timeout(Duration::from_secs(10))
            .build(manager)?;

        let db = Self {
            pool: Arc::new(pool),
            cipher,
        };
        db.initialise_schema()?;
        Ok(db)
    }

    fn get_conn(&self) -> Result<PooledConnection<SqliteConnectionManager>, DatabaseError> {
        Ok(self.pool.get()?)
    }

    fn initialise_schema(&self) -> Result<(), DatabaseError> {
        let mut conn = self.get_conn()?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                api_key_hash TEXT NOT NULL UNIQUE,
                scope TEXT,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                total_prompt_tokens INTEGER NOT NULL DEFAULT 0,
                total_completion_tokens INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS token_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_key_id INTEGER NOT NULL,
                model_name TEXT NOT NULL,
                prompt_tokens INTEGER NOT NULL,
                completion_tokens INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS model_downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo_id TEXT NOT NULL,
                revision TEXT NOT NULL DEFAULT 'latest',
                local_path TEXT NOT NULL,
                model_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                downloaded_at TEXT NOT NULL,
                UNIQUE(repo_id, revision)
            );

            CREATE TABLE IF NOT EXISTS provider_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                name TEXT NOT NULL,
                encrypted_secret BLOB NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(provider, name)
            );
            "#,
        )?;
        Ok(())
    }

    pub async fn bootstrap_admin(&self) -> Result<Option<String>, DatabaseError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<String>, DatabaseError> {
            let conn = pool.get()?;
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
            if count > 0 {
                return Ok(None);
            }
            let username = "admin".to_string();
            let password: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(32)
                .map(char::from)
                .collect();
            let salt = SaltString::generate(&mut rand::thread_rng());
            let argon2 = Argon2::default();
            let hash = argon2
                .hash_password(password.as_bytes(), &salt)?
                .to_string();
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
                params![username, hash, now],
            )?;
            Ok(Some(password))
        })
        .await?
    }

    pub async fn verify_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<UserRecord>, DatabaseError> {
        let pool = self.pool.clone();
        let username = username.to_owned();
        let password = password.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Option<UserRecord>, DatabaseError> {
            let conn = pool.get()?;
            let mut stmt =
                conn.prepare("SELECT id, password_hash FROM users WHERE username = ?1")?;
            let result = stmt.query_row([username.as_str()], |row| {
                let id: i64 = row.get(0)?;
                let password_hash: String = row.get(1)?;
                Ok((id, password_hash))
            });
            match result.optional()? {
                None => Ok(None),
                Some((id, password_hash)) => {
                    let parsed_hash = PasswordHash::new(&password_hash)?;
                    if Argon2::default()
                        .verify_password(password.as_bytes(), &parsed_hash)
                        .is_ok()
                    {
                        Ok(Some(UserRecord {
                            id,
                            username: username.clone(),
                        }))
                    } else {
                        Ok(None)
                    }
                }
            }
        })
        .await?
    }

    pub async fn create_session(
        &self,
        user_id: i64,
        ttl: Duration,
    ) -> Result<String, DatabaseError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<String, DatabaseError> {
            let conn = pool.get()?;
            let token: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(48)
                .map(char::from)
                .collect();
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let session_hash = hex::encode(hasher.finalize());
            let now = Utc::now();
            let expires_at = now + chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::hours(2));
            conn.execute(
                "INSERT INTO admin_sessions (user_id, session_hash, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![
                    user_id,
                    session_hash,
                    now.to_rfc3339(),
                    expires_at.to_rfc3339()
                ],
            )?;
            Ok(token)
        })
        .await?
    }

    pub async fn resolve_session(&self, token: &str) -> Result<Option<UserRecord>, DatabaseError> {
        let pool = self.pool.clone();
        let token = token.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Option<UserRecord>, DatabaseError> {
            let conn = pool.get()?;
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let session_hash = hex::encode(hasher.finalize());
            let now = Utc::now().to_rfc3339();
            let mut stmt = conn.prepare(
                "SELECT admin_sessions.user_id, users.username
                 FROM admin_sessions
                 JOIN users ON users.id = admin_sessions.user_id
                 WHERE session_hash = ?1 AND expires_at > ?2",
            )?;
            let result = stmt.query_row(params![session_hash, now], |row| {
                let user_id: i64 = row.get(0)?;
                let username: String = row.get(1)?;
                Ok(UserRecord {
                    id: user_id,
                    username,
                })
            });
            Ok(result.optional()?)
        })
        .await?
    }

    pub async fn revoke_session(&self, token: &str) -> Result<(), DatabaseError> {
        let pool = self.pool.clone();
        let token = token.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), DatabaseError> {
            let conn = pool.get()?;
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            let session_hash = hex::encode(hasher.finalize());
            conn.execute(
                "DELETE FROM admin_sessions WHERE session_hash = ?1",
                params![session_hash],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn create_api_key(
        &self,
        name: &str,
        scope: Option<&str>,
    ) -> Result<(String, ApiKeyRecord), DatabaseError> {
        let pool = self.pool.clone();
        let name = name.to_owned();
        let scope = scope.map(|s| s.to_owned());
        tokio::task::spawn_blocking(move || -> Result<(String, ApiKeyRecord), DatabaseError> {
            let conn = pool.get()?;
            let api_key: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(56)
                .map(char::from)
                .collect();
            let salt = SaltString::generate(&mut rand::thread_rng());
            let hash = Argon2::default()
                .hash_password(api_key.as_bytes(), &salt)?
                .to_string();
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO api_keys (name, api_key_hash, scope, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![name, hash, scope, now],
            )?;
            let id = conn.last_insert_rowid();
            Ok((api_key, ApiKeyRecord { id, name, scope }))
        })
        .await?
    }

    pub async fn verify_api_key(&self, token: &str) -> Result<Option<ApiKeyRecord>, DatabaseError> {
        let pool = self.pool.clone();
        let token = token.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Option<ApiKeyRecord>, DatabaseError> {
            let conn = pool.get()?;
            let mut stmt = conn.prepare("SELECT id, name, api_key_hash, scope FROM api_keys")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let id: i64 = row.get(0)?;
                let name: String = row.get(1)?;
                let hash: String = row.get(2)?;
                let scope: Option<String> = row.get(3)?;
                let parsed_hash = PasswordHash::new(&hash)?;
                if Argon2::default()
                    .verify_password(token.as_bytes(), &parsed_hash)
                    .is_ok()
                {
                    conn.execute(
                        "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
                        params![Utc::now().to_rfc3339(), id],
                    )?;
                    return Ok(Some(ApiKeyRecord { id, name, scope }));
                }
            }
            Ok(None)
        })
        .await?
    }

    pub async fn record_token_usage(
        &self,
        api_key_id: i64,
        model_name: &str,
        prompt_tokens: i64,
        completion_tokens: i64,
    ) -> Result<(), DatabaseError> {
        let pool = self.pool.clone();
        let model_name = model_name.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), DatabaseError> {
            let conn = pool.get()?;
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO token_usage (api_key_id, model_name, prompt_tokens, completion_tokens, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![api_key_id, model_name, prompt_tokens, completion_tokens, now],
            )?;
            conn.execute(
                "UPDATE api_keys SET total_prompt_tokens = total_prompt_tokens + ?1, total_completion_tokens = total_completion_tokens + ?2 WHERE id = ?3",
                params![prompt_tokens, completion_tokens, api_key_id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn upsert_model_download(
        &self,
        repo_id: &str,
        revision: Option<&str>,
        local_path: &str,
        model_type: &str,
        size_bytes: i64,
    ) -> Result<(), DatabaseError> {
        let pool = self.pool.clone();
        let repo_id = repo_id.to_owned();
        let revision = revision
            .map(|r| r.to_owned())
            .unwrap_or_else(|| "latest".to_string());
        let local_path = local_path.to_owned();
        let model_type = model_type.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), DatabaseError> {
            let conn = pool.get()?;
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO model_downloads (repo_id, revision, local_path, model_type, size_bytes, downloaded_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(repo_id, revision) DO UPDATE SET
                    local_path = excluded.local_path,
                    model_type = excluded.model_type,
                    size_bytes = excluded.size_bytes,
                    downloaded_at = excluded.downloaded_at",
                params![repo_id, revision, local_path, model_type, size_bytes, now],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn list_model_downloads(&self) -> Result<Vec<ModelDownloadRecord>, DatabaseError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<ModelDownloadRecord>, DatabaseError> {
            let conn = pool.get()?;
            let mut stmt = conn.prepare(
                "SELECT id, repo_id, revision, local_path, model_type, size_bytes, downloaded_at FROM model_downloads ORDER BY downloaded_at DESC",
            )?;
            let mut rows = stmt.query([])?;
            let mut downloads = Vec::new();
            while let Some(row) = rows.next()? {
                downloads.push(ModelDownloadRecord {
                    id: row.get(0)?,
                    repo_id: row.get(1)?,
                    revision: row.get(2)?,
                    local_path: row.get(3)?,
                    model_type: row.get(4)?,
                    size_bytes: row.get(5)?,
                    downloaded_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                });
            }
            Ok(downloads)
        })
        .await?
    }

    pub async fn store_provider_secret(
        &self,
        provider: &str,
        name: &str,
        secret: &str,
    ) -> Result<(), DatabaseError> {
        let pool = self.pool.clone();
        let cipher = self.cipher.clone();
        let provider = provider.to_owned();
        let name = name.to_owned();
        let secret = secret.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), DatabaseError> {
            let conn = pool.get()?;
            let encrypted = cipher.encrypt(secret.as_bytes())?;
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO provider_credentials (provider, name, encrypted_secret, created_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(provider, name) DO UPDATE SET encrypted_secret = excluded.encrypted_secret, created_at = excluded.created_at",
                params![provider, name, encrypted],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn get_provider_secret(
        &self,
        provider: &str,
        name: &str,
    ) -> Result<Option<String>, DatabaseError> {
        let pool = self.pool.clone();
        let cipher = self.cipher.clone();
        let provider = provider.to_owned();
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Option<String>, DatabaseError> {
            let conn = pool.get()?;
            let mut stmt = conn.prepare(
                "SELECT encrypted_secret FROM provider_credentials WHERE provider = ?1 AND name = ?2",
            )?;
            let encrypted: Option<Vec<u8>> = stmt
                .query_row(params![provider, name], |row| row.get(0))
                .optional()?;
            let Some(data) = encrypted else {
                return Ok(None);
            };
            let decrypted = cipher.decrypt(&data)?;
            let secret = String::from_utf8(decrypted).map_err(|_| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(fmt::Error),
                )
            })?;
            Ok(Some(secret))
        })
        .await?
    }

    pub async fn list_api_keys(&self) -> Result<Vec<ApiKeyRecord>, DatabaseError> {
        let pool = self.pool.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<ApiKeyRecord>, DatabaseError> {
            let conn = pool.get()?;
            let mut stmt =
                conn.prepare("SELECT id, name, scope FROM api_keys ORDER BY created_at DESC")?;
            let mut rows = stmt.query([])?;
            let mut keys = Vec::new();
            while let Some(row) = rows.next()? {
                keys.push(ApiKeyRecord {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    scope: row.get(2)?,
                });
            }
            Ok(keys)
        })
        .await?
    }
}
