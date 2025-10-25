use actix_multipart::form::{tempfile::TempFile, text::Text, MultipartForm};
use actix_web::{post, web::Data, HttpResponse, Responder};
use base64::Engine as _;
use futures::StreamExt;
use rand::seq::IndexedRandom;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    auth::ApiKeyIdentity, db::Database, manager::ModelManager, token::estimate_text_tokens,
    OpenAiError, ProcessAudio, ProcessTts,
};

#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub struct TranscriptionsResponse {
    pub text: String,
}

#[derive(Debug, MultipartForm)]
struct UploadForm {
    model: Text<String>,
    file: TempFile,
}

#[utoipa::path(
    responses(
        (status = OK, description = "Success", body = TranscriptionsResponse, content_type = "application/json")
    ),
    security(
        ("api_key" = [])
    ),
)]
#[post("/audio/transcriptions")]
pub async fn audio_transcriptions(
    api_key: ApiKeyIdentity,
    form: MultipartForm<UploadForm>,
    manager: Data<ModelManager>,
    db: Data<Database>,
) -> impl Responder {
    let asr_pool = manager.asr_pool().await;
    let Some(asr_pool) = asr_pool.get(&form.model.0) else {
        return HttpResponse::BadRequest().json(OpenAiError {
            message: format!(
                "The model {} does not exist or you do not have access to it.",
                form.model.0
            ),
            code: "model_not_found".to_owned(),
            r#type: "invalid_request_error".to_owned(),
            param: None,
        });
    };

    let mut rng = rand::rng();
    let asr = asr_pool.choose(&mut rng).unwrap();
    let path = form.file.file.as_ref().to_string_lossy().to_string();
    let send_future = asr.send(ProcessAudio::FilePath(path));

    match actix_web::rt::time::timeout(std::time::Duration::from_secs(5), send_future).await {
        Ok(Ok(Ok(receiver))) => {
            let sse_stream = receiver.map(move |content| match content {
                crate::AsrText::SenseVoice(voice_text) => voice_text.content,
            });

            let transcription_parts: Vec<String> = sse_stream.collect().await;
            let full_transcription = transcription_parts.join("");
            let prompt_tokens = 0;
            let completion_tokens = estimate_text_tokens(&full_transcription);
            if let Err(err) = db
                .record_token_usage(
                    api_key.id(),
                    &form.model.0,
                    prompt_tokens,
                    completion_tokens,
                )
                .await
            {
                return HttpResponse::InternalServerError().json(OpenAiError {
                    message: format!("Failed to record usage: {}", err),
                    code: "usage_record_error".to_owned(),
                    r#type: "internal_error".to_owned(),
                    param: None,
                });
            }
            HttpResponse::Ok().json(json!({ "text": full_transcription }))
        }
        Ok(Ok(Err(e))) => HttpResponse::InternalServerError().json(OpenAiError {
            message: format!("Internal processing error: {:?}", e),
            code: "processing_error".to_owned(),
            r#type: "internal_error".to_owned(),
            param: None,
        }),
        Err(_timeout) => HttpResponse::UnavailableForLegalReasons().json(OpenAiError {
            message: format!("Server Busy."),
            code: "server_".to_owned(),
            r#type: "internal_error".to_owned(),
            param: None,
        }),
        Ok(Err(e)) => HttpResponse::UnavailableForLegalReasons().json(OpenAiError {
            message: format!("Internal server error:{}", e),
            code: "server_".to_owned(),
            r#type: "internal_error".to_owned(),
            param: None,
        }),
    }
}

#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub struct SpeechRequest {
    pub model: String,
    pub input: String,
}

#[derive(Serialize, utoipa::ToSchema)]
pub struct SpeechResponse {
    pub audio_base64: String,
    pub mime_type: String,
}

#[utoipa::path(
    request_body = SpeechRequest,
    responses(
        (status = OK, description = "Success", body = SpeechResponse, content_type = "application/json")
    ),
    security(("api_key" = [])),
)]
#[post("/audio/speech")]
pub async fn audio_speech(
    api_key: ApiKeyIdentity,
    body: actix_web::web::Json<SpeechRequest>,
    manager: Data<ModelManager>,
    db: Data<Database>,
) -> impl Responder {
    let tts_pool = manager.tts_pool().await;
    let Some(pool) = tts_pool.get(&body.model) else {
        return HttpResponse::BadRequest().json(OpenAiError {
            message: format!(
                "The model {} does not exist or you do not have access to it.",
                body.model
            ),
            code: "model_not_found".to_owned(),
            r#type: "invalid_request_error".to_owned(),
            param: None,
        });
    };

    let mut rng = rand::rng();
    let tts = pool.choose(&mut rng).unwrap();
    match tts
        .send(ProcessTts {
            text: body.input.clone(),
        })
        .await
    {
        Ok(Ok(audio_bytes)) => {
            let usage_tokens = estimate_text_tokens(&body.input);
            if let Err(err) = db
                .record_token_usage(api_key.id(), &body.model, usage_tokens, usage_tokens)
                .await
            {
                return HttpResponse::InternalServerError().json(OpenAiError {
                    message: format!("Failed to record usage: {}", err),
                    code: "usage_record_error".to_owned(),
                    r#type: "internal_error".to_owned(),
                    param: None,
                });
            }
            let encoded = base64::engine::general_purpose::STANDARD.encode(audio_bytes);
            HttpResponse::Ok().json(SpeechResponse {
                audio_base64: encoded,
                mime_type: "audio/wav".to_string(),
            })
        }
        Ok(Err(_)) | Err(_) => HttpResponse::InternalServerError().json(OpenAiError {
            message: "Failed to generate speech".to_owned(),
            code: "tts_failure".to_owned(),
            r#type: "internal_error".to_owned(),
            param: None,
        }),
    }
}
