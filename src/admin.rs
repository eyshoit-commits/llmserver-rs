use actix_web::{
    delete, get, post,
    web::{self, Json, Path},
    HttpResponse, Responder,
};
use log::{error, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

use crate::db::{PgmlRepository, RegisterModelPayload, StoredModel};

const DASHBOARD_HTML: &str = include_str!("../assets/admin-dashboard.html");

#[derive(Debug, Serialize, ToSchema)]
pub struct RagModelListResponse {
    pub models: Vec<StoredModel>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminErrorResponse {
    pub message: String,
}

impl AdminErrorResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RagModelRequest {
    pub pipeline_name: String,
    pub model_uri: String,
    pub task: String,
    pub collection_name: String,
    #[serde(default)]
    pub metadata: Value,
}

#[utoipa::path(
    get,
    path = "/admin/api/models",
    responses(
        (status = OK, description = "List all registered PGML pipelines", body = RagModelListResponse),
        (status = SERVICE_UNAVAILABLE, description = "PGML repository is disabled", body = AdminErrorResponse)
    ),
    tag = "Admin"
)]
#[get("/models")]
pub async fn list_models(repo: web::Data<Option<PgmlRepository>>) -> impl Responder {
    let Some(repository) = repo.get_ref() else {
        return HttpResponse::ServiceUnavailable().json(AdminErrorResponse::new(
            "PGML repository is not configured. Set DATABASE_URL to enable the Admin dashboard.",
        ));
    };

    match repository.list_models().await {
        Ok(models) => HttpResponse::Ok().json(RagModelListResponse { models }),
        Err(err) => {
            error!("Failed to list PGML models: {}", err);
            HttpResponse::InternalServerError().json(AdminErrorResponse::new(
                "Unable to query PGML model registry",
            ))
        }
    }
}

#[utoipa::path(
    post,
    path = "/admin/api/models",
    request_body = RagModelRequest,
    responses(
        (status = OK, description = "Model registered or updated", body = StoredModel),
        (status = SERVICE_UNAVAILABLE, description = "PGML repository is disabled", body = AdminErrorResponse),
        (status = BAD_REQUEST, description = "Invalid payload", body = AdminErrorResponse)
    ),
    tag = "Admin"
)]
#[post("/models")]
pub async fn register_model(
    repo: web::Data<Option<PgmlRepository>>,
    payload: Json<RagModelRequest>,
) -> impl Responder {
    let Some(repository) = repo.get_ref() else {
        return HttpResponse::ServiceUnavailable().json(AdminErrorResponse::new(
            "PGML repository is not configured. Set DATABASE_URL to enable the Admin dashboard.",
        ));
    };

    if payload.pipeline_name.trim().is_empty()
        || payload.model_uri.trim().is_empty()
        || payload.task.trim().is_empty()
        || payload.collection_name.trim().is_empty()
    {
        return HttpResponse::BadRequest().json(AdminErrorResponse::new(
            "All fields are required to register a PGML pipeline",
        ));
    }

    match repository
        .register_model(RegisterModelPayload {
            pipeline_name: &payload.pipeline_name,
            model_uri: &payload.model_uri,
            task: &payload.task,
            collection_name: &payload.collection_name,
            metadata: payload.metadata.clone(),
        })
        .await
    {
        Ok(model) => HttpResponse::Ok().json(model),
        Err(err) => {
            error!(
                "Failed to register PGML model {}: {}",
                payload.pipeline_name, err
            );
            HttpResponse::InternalServerError()
                .json(AdminErrorResponse::new("Unable to register PGML model"))
        }
    }
}

#[utoipa::path(
    delete,
    path = "/admin/api/models/{pipeline_name}",
    params(("pipeline_name" = String, Path, description = "Pipeline identifier to drop")),
    responses(
        (status = NO_CONTENT, description = "Pipeline deleted"),
        (status = SERVICE_UNAVAILABLE, description = "PGML repository is disabled", body = AdminErrorResponse)
    ),
    tag = "Admin"
)]
#[delete("/models/{pipeline_name}")]
pub async fn delete_model(
    repo: web::Data<Option<PgmlRepository>>,
    pipeline_name: Path<String>,
) -> impl Responder {
    let Some(repository) = repo.get_ref() else {
        return HttpResponse::ServiceUnavailable().json(AdminErrorResponse::new(
            "PGML repository is not configured. Set DATABASE_URL to enable the Admin dashboard.",
        ));
    };

    let pipeline_name = pipeline_name.into_inner();

    match repository.delete_model(&pipeline_name).await {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(err) => {
            warn!("Failed to delete PGML model {}: {}", pipeline_name, err);
            HttpResponse::InternalServerError()
                .json(AdminErrorResponse::new("Unable to delete PGML model"))
        }
    }
}

pub async fn dashboard(repo: web::Data<Option<PgmlRepository>>) -> impl Responder {
    if repo.get_ref().is_none() {
        return HttpResponse::ServiceUnavailable().body(
            "<html><body><h1>PGML dashboard disabled</h1><p>Set the DATABASE_URL environment variable to enable the admin interface.</p></body></html>",
        );
    }

    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(DASHBOARD_HTML)
}
