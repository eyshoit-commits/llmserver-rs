use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub enum ModelType {
    #[default]
    LLM,
    ASR,
    TTS,
}

impl std::fmt::Display for ModelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            ModelType::LLM => "LLM",
            ModelType::ASR => "ASR",
            ModelType::TTS => "TTS",
        };
        write!(f, "{value}")
    }
}

impl std::str::FromStr for ModelType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "LLM" | "llm" => Ok(ModelType::LLM),
            "ASR" | "asr" => Ok(ModelType::ASR),
            "TTS" | "tts" => Ok(ModelType::TTS),
            other => Err(format!("unknown model type: {other}")),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ModelConfig {
    pub model_repo: String,
    pub model_name: String,
    pub model_type: ModelType,
    pub model_path: Option<String>,
    #[serde(skip_deserializing)]
    pub _asserts_path: String,
    pub cache_path: Option<String>,
    pub think: Option<bool>,
}
