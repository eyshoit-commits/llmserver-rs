use std::pin::Pin;
use actix::Actor;
use hf_hub::api::sync::Api;
use rkllm_rs::prelude::*;
use serde::Deserialize;
use serde_variant::to_variant_name;
use tokio_stream::wrappers::ReceiverStream;

use super::AIModel;
use super::ProcessMessages;
use super::ShutdownMessages;
use super::LLM;

use autotokenizer::AutoTokenizer;
use autotokenizer::DefaultPromptMessage;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SimpleLLMConfig {
    pub modle_path: String,
    pub cache_path: Option<String>,
    pub think: bool,
}

#[derive(Debug)]
pub struct SimpleRkLLM {
    handle: LLMHandle,
    atoken: AutoTokenizer,
    infer_params: RKLLMInferParam,
    config: SimpleLLMConfig,
}

impl Actor for SimpleRkLLM {
    type Context = actix::Context<Self>;
}

impl actix::Handler<ProcessMessages> for SimpleRkLLM {
    type Result = Result<Pin<Box<dyn futures::Stream<Item = String> + Send + 'static>>, ()>;

    fn handle(&mut self, msg: ProcessMessages, _ctx: &mut Self::Context) -> Self::Result {
        let (tx, rx) = tokio::sync::mpsc::channel(8192);

        let atoken = self.atoken.clone();

        let prompt = msg
            .messages
            .iter()
            .map(|a| {
                let content = match &a.content {
                    Some(crate::chat::Content::String(s)) => s,
                    Some(crate::chat::Content::Array(items)) => &items.join(""),
                    None => "", // 老實說不應該發生
                };
                DefaultPromptMessage::new(to_variant_name(&a.role).unwrap(), &content)
            })
            .collect::<Vec<_>>();

        let mut input = match atoken.apply_chat_template(prompt, true) {
            Ok(parsed) => parsed,
            Err(_) => {
                println!("apply_chat_template failed.");
                "".to_owned()
            }
        };
        // TODO: 用參數判斷要不要think
        if !self.config.think {
            input += "\n\n</think>\n\n";
        }

        let handle = self.handle.clone();
        let infer_params_cloned = self.infer_params.clone();
        actix_web::rt::spawn(async move {
            let cb = CallbackSendSelfChannel { sender: Some(tx) };
            handle.run(RKLLMInput::Prompt(input), Some(infer_params_cloned), cb);
        });

        // 將 Receiver 轉換為 Stream
        let stream = ReceiverStream::new(rx);
        Ok(Box::pin(stream))
    }
}

impl actix::Handler<ShutdownMessages> for SimpleRkLLM {
    type Result = Result<(), ()>;

    fn handle(&mut self, _: ShutdownMessages, _: &mut Self::Context) -> Self::Result {
        self.handle.destroy();
        Ok(())
    }
}

impl AIModel for SimpleRkLLM {
    type Config = SimpleLLMConfig;
    fn init(
        config: &SimpleLLMConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut param = RKLLMParam {
            ..Default::default()
        };
        let api = Api::new().unwrap();
        let repo = api.model(config.modle_path.clone());
        let binding = repo.get("model.rkllm")?;
        let modle_path = binding.to_string_lossy();
        param.model_path = modle_path.as_ptr();
        let handle = rkllm_init(&mut param)?;
        let atoken = AutoTokenizer::from_pretrained(config.modle_path.clone(), None)?;

        let infer_params = RKLLMInferParam {
            mode: RKLLMInferMode::InferGenerate,
            lora_params: None,
            prompt_cache_params: if let Some(cache_path) = &config.cache_path {
                Some(RKLLMPromptCacheParam {
                    save_prompt_cache: true,
                    prompt_cache_path: cache_path.to_owned(),
                })
            } else {
                None
            },
        };

        Ok(SimpleRkLLM {
            handle,
            atoken,
            infer_params,
            config: config.clone(),
        })
    }
}

impl LLM for SimpleRkLLM {}

struct CallbackSendSelfChannel {
    sender: Option<tokio::sync::mpsc::Sender<String>>,
}
impl RkllmCallbackHandler for CallbackSendSelfChannel {
    fn handle(&mut self, result: Option<RKLLMResult>, state: LLMCallState) {
        match state {
            LLMCallState::Normal => {
                if let Some(result) = result {
                    if let Some(sender) = &self.sender {
                        while sender.try_send(result.text.clone()).is_err() {
                            std::thread::yield_now();
                        }
                    }
                }
            }
            LLMCallState::Waiting => {}
            LLMCallState::Finish => {
                drop(self.sender.take());
            }
            LLMCallState::Error => {}
            LLMCallState::GetLastHiddenLayer => {}
        }
    }
}
