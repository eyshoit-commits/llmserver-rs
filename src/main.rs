use std::path::PathBuf;
use std::sync::Arc;

use actix_files::Files;
use actix_session::{config::PersistentSession, storage::CookieSessionStore, SessionMiddleware};
use actix_web::cookie::Key;
use actix_web::{get, middleware::Logger, web, App, HttpResponse, HttpServer, Result};
use llmserver_rs::{
    api_keys, audio, auth, chat, database,
    encryption::EncryptionService,
    huggingface, models,
    state::{AppState, ModelManager},
    tts,
};

#[get("/health")]
async fn health() -> &'static str {
    ""
}

fn decode_hex_key(value: &str, expected_len: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = hex::decode(value)?;
    if bytes.len() != expected_len {
        return Err(format!("expected {expected_len} bytes but decoded {}", bytes.len()).into());
    }
    Ok(bytes)
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var(
        "RUST_LOG",
        std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string()),
    );
    env_logger::init();

    let database_url = std::env::var("LLMSERVER_DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://data/app.db".to_string());
    if let Some(path) = database_url.strip_prefix("sqlite://") {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let pool = database::init_pool(&database_url).await?;
    database::run_migrations(&pool).await?;
    auth::ensure_initial_admin(&pool)
        .await
        .map_err(|e| Box::new(e) as _)?;

    let encryption_hex = std::env::var("LLMSERVER_ENCRYPTION_KEY")
        .expect("LLMSERVER_ENCRYPTION_KEY must be set to a 64-character hex string");
    let encryption = EncryptionService::new_from_hex(&encryption_hex)
        .map_err(|e| format!("invalid encryption key: {e}"))?;

    let session_hex = std::env::var("LLMSERVER_SESSION_KEY")
        .expect("LLMSERVER_SESSION_KEY must be set to a 128-character hex string (64 bytes)");
    let session_key_bytes = decode_hex_key(&session_hex, 64)?;
    let session_key = Key::from(&session_key_bytes);

    let cache_dir = std::env::var("LLMSERVER_HF_CACHE").unwrap_or_else(|_| "hf-cache".to_string());
    std::fs::create_dir_all(&cache_dir)?;
    let huggingface_cache = PathBuf::from(cache_dir);

    let http_client = reqwest::Client::builder()
        .user_agent(format!("llmserver-rs/{}", env!("CARGO_PKG_VERSION")))
        .build()?;

    let app_state = AppState {
        pool: pool.clone(),
        model_manager: ModelManager::new(),
        encryption: Arc::new(encryption),
        http_client,
        huggingface_cache: huggingface_cache.clone(),
    };

    if let Err(err) = models::resume_running_models(&app_state).await {
        log::error!("failed to resume models: {err}");
    }

    let bind_address =
        std::env::var("LLMSERVER_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8443".to_string());

    HttpServer::new(move || {
        let session_middleware =
            SessionMiddleware::builder(CookieSessionStore::default(), session_key.clone())
                .session_lifecycle(
                    PersistentSession::default()
                        .session_ttl(actix_web::cookie::time::Duration::hours(12)),
                )
                .cookie_secure(false)
                .build();

        App::new()
            .wrap(Logger::default())
            .wrap(session_middleware)
            .app_data(web::Data::new(app_state.clone()))
            .service(
                web::scope("/v1")
                    .service(chat::chat_completions)
                    .service(audio::audio_transcriptions)
                    .service(tts::text_to_speech),
            )
            .service(
                web::scope("/admin/api")
                    .route("/login", web::post().to(auth::login))
                    .route("/logout", web::post().to(auth::logout))
                    .route("/session", web::get().to(auth::current_admin))
                    .route("/users", web::post().to(auth::create_admin))
                    .route("/api-keys", web::get().to(api_keys::list_api_keys))
                    .route("/api-keys", web::post().to(api_keys::create_api_key))
                    .route("/api-keys/{id}", web::patch().to(api_keys::update_api_key))
                    .route("/api-keys/{id}", web::delete().to(api_keys::delete_api_key))
                    .route("/hf-tokens", web::get().to(huggingface::list_tokens))
                    .route("/hf-tokens", web::put().to(huggingface::upsert_token))
                    .route(
                        "/hf-tokens/{name}",
                        web::delete().to(huggingface::delete_token),
                    )
                    .route("/models", web::get().to(models::list_models))
                    .route("/models", web::post().to(models::create_model))
                    .route("/models/{id}", web::get().to(models::get_model))
                    .route("/models/{id}", web::delete().to(models::delete_model))
                    .route(
                        "/models/{id}/download",
                        web::post().to(models::download_model),
                    )
                    .route("/models/{id}/start", web::post().to(models::start_model))
                    .route("/models/{id}/stop", web::post().to(models::stop_model)),
            )
            .service(health)
            .service(Files::new("/admin", "./assets/admin").index_file("index.html"))
    })
    .bind(bind_address)?
    .run()
    .await?;

    Ok(())
}
