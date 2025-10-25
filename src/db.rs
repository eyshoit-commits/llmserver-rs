use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use deadpool_postgres::{Manager, Pool};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_postgres::{error::SqlState, types::Json, Config as PgConfig, NoTls, Row};
use utoipa::ToSchema;

/// Name of the environment variable that stores the Postgres connection string.
const DATABASE_URL_ENV: &str = "DATABASE_URL";

/// Shared repository that encapsulates PGML specific metadata management.
#[derive(Clone)]
pub struct PgmlRepository {
    pool: Pool,
}

impl PgmlRepository {
    /// Attempt to create a repository from the `DATABASE_URL` environment variable.
    ///
    /// If the environment variable is missing or blank the function returns `Ok(None)`
    /// so that the API server can continue to operate without PGML features.
    pub async fn try_from_env() -> Result<Option<Self>> {
        let database_url = match std::env::var(DATABASE_URL_ENV) {
            Ok(value) if !value.trim().is_empty() => value,
            Ok(_) | Err(_) => return Ok(None),
        };

        let pg_config = PgConfig::from_str(&database_url)
            .with_context(|| format!("Invalid database URL: {database_url}"))?;
        let manager = Manager::new(pg_config, NoTls);
        let pool = Pool::builder(manager)
            .max_size(16)
            .build()
            .map_err(|err| anyhow!(err))?;

        let repository = Self { pool };
        repository.initialise().await?;
        info!("Connected to PGML database via {DATABASE_URL_ENV}");

        Ok(Some(repository))
    }

    async fn initialise(&self) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .batch_execute(
                r#"
                CREATE EXTENSION IF NOT EXISTS vector;
                CREATE EXTENSION IF NOT EXISTS pgml;

                CREATE TABLE IF NOT EXISTS admin_rag_models (
                    pipeline_name TEXT PRIMARY KEY,
                    model_uri TEXT NOT NULL,
                    task TEXT NOT NULL,
                    collection_name TEXT NOT NULL,
                    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                    last_status TEXT NOT NULL DEFAULT 'registered',
                    last_error TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

                CREATE OR REPLACE FUNCTION admin_rag_models_set_updated_at()
                RETURNS TRIGGER AS $$
                BEGIN
                    NEW.updated_at = NOW();
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;

                DROP TRIGGER IF EXISTS trg_admin_rag_models_updated_at ON admin_rag_models;
                CREATE TRIGGER trg_admin_rag_models_updated_at
                    BEFORE UPDATE ON admin_rag_models
                    FOR EACH ROW
                    EXECUTE FUNCTION admin_rag_models_set_updated_at();
                "#,
            )
            .await?;
        Ok(())
    }

    pub async fn list_models(&self) -> Result<Vec<StoredModel>> {
        let client = self.pool.get().await?;
        let rows = client
            .query(
                r#"
                SELECT
                    pipeline_name,
                    model_uri,
                    task,
                    collection_name,
                    metadata,
                    last_status,
                    last_error,
                    created_at,
                    updated_at
                FROM admin_rag_models
                ORDER BY pipeline_name
                "#,
                &[],
            )
            .await?;

        Ok(rows.into_iter().map(StoredModel::from).collect())
    }

    pub async fn register_model(&self, payload: RegisterModelPayload<'_>) -> Result<StoredModel> {
        let client = self.pool.get().await?;
        let (status, error_message) = match client
            .execute(
                "SELECT pgml.load_model($1::text, $2::text, $3::text)",
                &[&payload.pipeline_name, &payload.model_uri, &payload.task],
            )
            .await
        {
            Ok(_) => ("loaded".to_owned(), None),
            Err(err) => {
                error!(
                    "Failed to load PGML pipeline {}: {}",
                    payload.pipeline_name, err
                );
                ("error".to_owned(), Some(err.to_string()))
            }
        };

        let metadata = Json(payload.metadata);

        client
            .execute(
                r#"
                INSERT INTO admin_rag_models (
                    pipeline_name,
                    model_uri,
                    task,
                    collection_name,
                    metadata,
                    last_status,
                    last_error
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (pipeline_name) DO UPDATE SET
                    model_uri = EXCLUDED.model_uri,
                    task = EXCLUDED.task,
                    collection_name = EXCLUDED.collection_name,
                    metadata = EXCLUDED.metadata,
                    last_status = EXCLUDED.last_status,
                    last_error = EXCLUDED.last_error,
                    updated_at = NOW()
                "#,
                &[
                    &payload.pipeline_name,
                    &payload.model_uri,
                    &payload.task,
                    &payload.collection_name,
                    &metadata,
                    &status,
                    &error_message,
                ],
            )
            .await?;

        let row = client
            .query_one(
                r#"
                SELECT
                    pipeline_name,
                    model_uri,
                    task,
                    collection_name,
                    metadata,
                    last_status,
                    last_error,
                    created_at,
                    updated_at
                FROM admin_rag_models
                WHERE pipeline_name = $1
                "#,
                &[&payload.pipeline_name],
            )
            .await?;

        Ok(StoredModel::from(row))
    }

    pub async fn delete_model(&self, pipeline_name: &str) -> Result<()> {
        let client = self.pool.get().await?;

        if let Err(err) = client
            .execute("SELECT pgml.drop_model($1::text)", &[&pipeline_name])
            .await
        {
            if let Some(db_error) = err.as_db_error() {
                if db_error.code() != &SqlState::UNDEFINED_FUNCTION {
                    warn!("PGML drop_model failed for {}: {}", pipeline_name, err);
                }
            } else {
                warn!("PGML drop_model failed for {}: {}", pipeline_name, err);
            }
        }

        client
            .execute(
                "DELETE FROM admin_rag_models WHERE pipeline_name = $1",
                &[&pipeline_name],
            )
            .await?;

        Ok(())
    }
}

/// Input payload used when registering a model.
pub struct RegisterModelPayload<'a> {
    pub pipeline_name: &'a str,
    pub model_uri: &'a str,
    pub task: &'a str,
    pub collection_name: &'a str,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StoredModel {
    pub pipeline_name: String,
    pub model_uri: String,
    pub task: String,
    pub collection_name: String,
    pub metadata: Value,
    pub last_status: String,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Row> for StoredModel {
    fn from(row: Row) -> Self {
        let metadata: Value = row
            .try_get::<_, Json<Value>>("metadata")
            .map(|json| json.0)
            .unwrap_or_else(|_| Value::Null);

        Self {
            pipeline_name: row.get("pipeline_name"),
            model_uri: row.get("model_uri"),
            task: row.get("task"),
            collection_name: row.get("collection_name"),
            metadata,
            last_status: row.get("last_status"),
            last_error: row.get("last_error"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

/// Helper used by tests to register a model without needing to construct the payload manually.
pub async fn upsert_model(
    repo: &PgmlRepository,
    payload: RegisterModelPayload<'_>,
) -> Result<StoredModel> {
    repo.register_model(payload).await
}
