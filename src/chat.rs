use actix_web::{
    post,
    web::{self, Json},
    HttpRequest, HttpResponse, Responder,
};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use crate::state::AppState;
use crate::{
    api_keys::{extract_api_key, record_token_usage, validate_api_key},
    tokenizer::{count_messages_tokens, count_text_tokens},
    Content, Message, OpenAiError, ProcessMessages, Role,
};

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct Delta {
    #[schema(value_type = Role)]
    pub role: Role,
    #[schema(value_type = Content)]
    pub content: Content,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub enum Stop {
    String(String),
    Array(Vec<String>),
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct ResponseFormat {
    //#[schema(enum = ["json_object", "json_object"])]
    pub r#type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct Function {
    pub name: String,
    pub description: Option<String>,
    pub parameters: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub struct Tool {
    pub r#type: String,
    pub function: Function,
}

#[derive(Debug, Clone, Deserialize, Serialize, utoipa::ToSchema)]
pub enum ToolChoice {
    Auto,
    None,
    Function { name: String },
}

#[derive(Deserialize, Serialize, utoipa::ToSchema, Default)]
#[schema(
    example = json!({
        "model": "DeepSeek-R1-Distill-Qwen-1.5B",
        "messages": [
            {
                "role": "developer",
                "content": "你是一個愚蠢的智慧音箱。除非使用者特別要求回答盡量短促。"
            },
            {
                "role": "user",
                "content": "你好，請問5+3等於多少!"
            }
        ]
    })
)]
#[derive(Debug, Clone)]
pub struct ChatCompletionsRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub temperature: Option<f32>,
    pub top_p: Option<f32>,
    pub n: Option<i32>,
    pub stream: Option<bool>,
    pub stop: Option<Stop>,
    pub max_tokens: Option<i32>,
    pub presence_penalty: Option<f32>,
    pub frequency_penalty: Option<f32>,
    pub logit_bias: Option<HashMap<i32, f32>>,
    pub user: Option<String>,
    pub response_format: Option<ResponseFormat>,
    pub seed: Option<i32>,
    pub tools: Option<Vec<Tool>>,
    pub tool_choice: Option<ToolChoice>,
    pub metadata: Option<HashMap<String, String>>,
}

#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub enum FinishReason {
    Stop,
    Length,
    FunctionCall,
    InvalidRequestError,
    ModelError,
    InternalError,
}

#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub struct Choice {
    pub index: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<Message>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<Message>,
    #[schema(value_type = String)]
    pub finish_reason: Option<FinishReason>,
}

#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub struct Usage {
    pub completion_tokens: i32,
    pub prompt_tokens: i32,
    pub total_tokens: i32,
}

#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub struct ChatCompletionsResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub choices: Vec<Choice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<Usage>,
}

#[utoipa::path(
    request_body = ChatCompletionsRequest,
    responses(
        (status = OK, description = "Success", body = ChatCompletionsResponse, content_type = "application/json")
    ),
    security(
        ("api_key" = [])
    ),
)]
#[post("/chat/completions")]
pub async fn chat_completions(
    req: HttpRequest,
    body: Json<ChatCompletionsRequest>,
    state: web::Data<AppState>,
) -> impl Responder {
    let id = "123".to_owned(); // Todo: 要改從資料庫拿
    let created = SystemTime::now();
    let created = created
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let Some(api_key) = extract_api_key(&req) else {
        return HttpResponse::Unauthorized().finish();
    };

    let api_key_info = match validate_api_key(&state.pool, &api_key).await {
        Ok(Some(info)) => info,
        Ok(None) => return HttpResponse::Unauthorized().finish(),
        Err(err) => return err,
    };

    if body.stream.unwrap_or(false) {
        return HttpResponse::NotImplemented().json(OpenAiError {
            message: "Streaming responses are not supported when API key enforcement is enabled."
                .to_string(),
            code: "stream_not_supported".to_owned(),
            r#type: "invalid_request_error".to_owned(),
            param: None,
        });
    }

    let prompt_tokens = count_messages_tokens(&body.messages);
    if let Some(limit) = api_key_info.token_limit {
        let current_total = api_key_info.prompt_tokens_used + api_key_info.completion_tokens_used;
        if current_total + prompt_tokens >= limit {
            return HttpResponse::TooManyRequests().json(OpenAiError {
                message: "token quota exceeded".to_owned(),
                code: "quota_exceeded".to_owned(),
                r#type: "rate_limit_exceeded".to_owned(),
                param: None,
            });
        }
    }

    let Some(llm) = state.model_manager.choose_llm(&body.model).await else {
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

    let send_future = llm.send(ProcessMessages {
        messages: body.messages.clone(),
    });

    match actix_web::rt::time::timeout(std::time::Duration::from_secs(5), send_future).await {
        Ok(Ok(Ok(receiver))) => {
            let chunks = receiver.collect::<Vec<_>>().await;
            let content = chunks.join("");
            let completion_tokens = count_text_tokens(&content);

            let usage = Usage {
                completion_tokens: completion_tokens as i32,
                prompt_tokens: prompt_tokens as i32,
                total_tokens: (completion_tokens + prompt_tokens) as i32,
            };

            if let Err(err) = record_token_usage(
                &state.pool,
                &api_key_info.id,
                &body.model,
                prompt_tokens,
                completion_tokens,
            )
            .await
            {
                return err;
            }

            let object = "chat.completion".to_owned();
            let choices = vec![Choice {
                index: 0,
                message: Some(Message {
                    role: Some(Role::Assistant),
                    content: Some(Content::String(content)),
                }),
                delta: None,
                finish_reason: Some(FinishReason::Stop),
            }];

            HttpResponse::Ok().json(ChatCompletionsResponse {
                id,
                object,
                created,
                choices,
                usage: Some(usage),
            })
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
