use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenAiError {
    pub message: String,
    pub r#type: String,
    pub param: Option<String>,
    pub code: String,
}