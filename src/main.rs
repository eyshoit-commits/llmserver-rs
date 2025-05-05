use actix::{Actor, Recipient};
use clap::{Arg, ArgAction, Command};
use serde::Deserialize;
use std::{collections::HashMap, fs::File, io::BufReader, net::Ipv4Addr};

use actix_web::{head, middleware::Logger, App, HttpServer, Result};
use llmserver_rs::{
    asr::simple::SimpleASRConfig, llm::simple::SimpleLLMConfig, AIModel, ProcessAudio,
    ProcessMessages, ShutdownMessages,
};
use utoipa_actix_web::{scope, AppExt};
use utoipa_swagger_ui::SwaggerUi;

/// Get health of the API.
#[utoipa::path(
    responses(
        (status = OK, description = "Success", body = str, content_type = "text/plain")
    )
)]
#[head("/health")]
async fn health() -> &'static str {
    ""
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    std::env::set_var("RUST_LOG", "info");
    env_logger::init();

    let matches = Command::new("rkllm")
        .about("Stupid webserver ever!")
        .version(VERSION)
        .arg_required_else_help(true)
        .arg(Arg::new("model_name"))
        .arg(
            Arg::new("instances")
                .short('i')
                .help("How many llm instances do you want to create.")
                .action(ArgAction::Set)
                .num_args(1),
        )
        .get_matches();

    //初始化模型
    let mut num_instances = 1; // 根據資源設定

    if let Some(value) = matches.get_one::<usize>("instances") {
        num_instances = *value;
    }
    let model_name = matches.get_one::<String>("model_name").unwrap();

    // Text type LLM
    let mut llm_recipients = HashMap::<String, Vec<Recipient<ProcessMessages>>>::new();
    let mut shutdown_recipients = Vec::new();
    for _ in 0..num_instances {
        let (llm, modelname) = match (*model_name).as_str() {
            "kautism/DeepSeek-R1-Distill-Qwen-1.5B-RK3588S-RKLLM1.1.4" => {
                let config_path = "assets/config/deepseek-1.5b.json";
                let file =
                    File::open(config_path).expect(&format!("Config {} not found!", config_path));
                let mut de = serde_json::Deserializer::from_reader(BufReader::new(file));
                let config = SimpleLLMConfig::deserialize(&mut de)?;
                (
                    llmserver_rs::llm::simple::SimpleRkLLM::init(&config),
                    config.modle_name.clone(),
                )
            }
            "kautism/DeepSeek-R1-Distill-Qwen-7B-RK3588S-RKLLM1.1.4" => {
                let config_path = "assets/config/deepseek-7b.json";
                let file =
                    File::open(config_path).expect(&format!("Config {} not found!", config_path));
                let mut de = serde_json::Deserializer::from_reader(BufReader::new(file));
                let config = SimpleLLMConfig::deserialize(&mut de)?;
                (
                    llmserver_rs::llm::simple::SimpleRkLLM::init(&config),
                    config.modle_name.clone(),
                )
            }
            "thanhtantran/gemma-3-1b-it-rk3588-1.2.0" => {
                let config_path = "assets/config/gemma-3-1b-it-rk3588-1.2.0.json";
                let file =
                    File::open(config_path).expect(&format!("Config {} not found!", config_path));
                let mut de = serde_json::Deserializer::from_reader(BufReader::new(file));
                let config = SimpleLLMConfig::deserialize(&mut de)?;
                (
                    llmserver_rs::llm::simple::SimpleRkLLM::init(&config),
                    config.modle_name.clone(),
                )
            }
            _ => {continue;},
        };
        println!("Model : {:?}", llm);
        let addr = llm.unwrap().start(); // 啟動 Actor，一次即可
        if let Some(vec) = llm_recipients.get_mut(&modelname) {
            vec.push(addr.clone().recipient::<ProcessMessages>());
        } else {
            llm_recipients.insert(modelname, vec![addr.clone().recipient::<ProcessMessages>()]);
        }
        shutdown_recipients.push(addr.clone().recipient::<ShutdownMessages>());
    }

    //let mut
    let mut audio_recipients = HashMap::<String, Vec<Recipient<ProcessAudio>>>::new();
    for _ in 0..num_instances {
        let (llm, modelname) = match (*model_name).as_str() {
            "happyme531/SenseVoiceSmall-RKNN2" => {
                let config_path = "assets/config/sensevoicesmall.json";
                let file =
                    File::open(config_path).expect(&format!("Config {} not found!", config_path));
                let mut de = serde_json::Deserializer::from_reader(BufReader::new(file));
                let config = SimpleASRConfig::deserialize(&mut de)?;
                (
                    llmserver_rs::asr::simple::SimpleASR::init(&config),
                    config.modle_name.clone(),
                )
            }
            _ => {continue;},
        };
        let addr = llm.unwrap().start(); // 啟動 Actor，一次即可
        if let Some(vec) = audio_recipients.get_mut(&modelname) {
            vec.push(addr.clone().recipient::<ProcessAudio>());
        } else {
            audio_recipients.insert(modelname, vec![addr.clone().recipient::<ProcessAudio>()]);
        }
        shutdown_recipients.push(addr.clone().recipient::<ShutdownMessages>());
    }
    if audio_recipients.len() == 0 && llm_recipients.len() == 0 {
        panic!("You do not load any model");
    }

    HttpServer::new(move || {
        let (app, api) = App::new()
            .app_data(actix_web::web::Data::new(llm_recipients.clone()))
            .app_data(actix_web::web::Data::new(audio_recipients.clone()))
            .into_utoipa_app()
            .map(|app| app.wrap(Logger::default()))
            .service(
                scope::scope("/v1")
                    .service(llmserver_rs::chat::chat_completions)
                    .service(llmserver_rs::audio::audio_transcriptions),
            )
            .service(health)
            .split_for_parts();

        app.service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", api))
    })
    .bind((Ipv4Addr::UNSPECIFIED, 8080))?
    .run()
    .await?;

    let shutdowns = shutdown_recipients.into_iter().map(|addr| async move {
        let _ = addr.send(ShutdownMessages).await.unwrap();
    });

    tokio::spawn(async {
        futures::future::join_all(shutdowns).await;
    })
    .await?;
    Ok(())
}
