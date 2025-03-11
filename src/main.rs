use actix::Actor;
use clap::{Arg, ArgAction, Command};
use serde::Deserialize;
use std::{fs::File, io::BufReader, net::Ipv4Addr};

use actix_web::{head, middleware::Logger, App, HttpServer, Result};
use llmserver_rs::llm::{simple::SimpleLLMConfig, AIModel, ProcessMessages, ShutdownMessages};
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

    // 跑起LLM
    let mut process_recipients = Vec::new();
    let mut shutdown_recipients = Vec::new();
    for _ in 0..num_instances {
        let llm = match (*model_name).as_str() {
            "kautism/DeepSeek-R1-Distill-Qwen-1.5B-RK3588S-RKLLM1.1.4" => {
                let file = File::open("assets/config/simplerkllm.json").expect("Config simplerkllm.json not found!");
                let mut de = serde_json::Deserializer::from_reader(BufReader::new(file));
                let config = SimpleLLMConfig::deserialize(&mut de)?;
                llmserver_rs::llm::simple::SimpleRkLLM::init(&config)
            }
            _ => Err(format!("Unknown model: {}", model_name).into()),
        }
        .unwrap();
        let addr = llm.start(); // 啟動 Actor，一次即可
        process_recipients.push(addr.clone().recipient::<ProcessMessages>());
        shutdown_recipients.push(addr.clone().recipient::<ShutdownMessages>());
    }
    HttpServer::new(move || {
        let (app, api) = App::new()
            .app_data(actix_web::web::Data::new(process_recipients.clone()))
            .into_utoipa_app()
            .map(|app| app.wrap(Logger::default()))
            .service(scope::scope("/v1").service(llmserver_rs::chat::chat_completions))
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
