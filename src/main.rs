use std::path::PathBuf;
use std::sync::Arc;

use actix_web::{head, middleware::Logger, web, App, HttpServer, Result};
use llmserver_rs::{
    admin, asr::simple::SimpleASRConfig, db::PgmlRepository, utils::ModelConfig, AIModel,
    ProcessAudio, ProcessMessages, ShutdownMessages,
};
use log::warn;
use utoipa_actix_web::{scope, AppExt};
use utoipa_swagger_ui::SwaggerUi;

fn load_model_configs() -> Result<HashMap<String, ModelConfig>, Box<dyn std::error::Error>> {
    let dir_path = "assets/config";
    let entries = fs::read_dir(dir_path).map_err(|e| e.to_string())?;

    let mut configs: HashMap<String, ModelConfig> = HashMap::new();

    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();

        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("json") {
            let mut file = fs::File::open(&path).map_err(|e| e.to_string())?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)
                .map_err(|e| e.to_string())?;

            let mut config: ModelConfig =
                serde_json::from_str(&contents).map_err(|e| e.to_string())?;
            println!("Loaded model config: {:?}", path.display());
            config._asserts_path = path.to_string_lossy().to_string();
            configs.insert(config.model_repo.clone(), config);
        }
    }

    Ok(configs)
}

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

    let pgml_repository = match PgmlRepository::try_from_env().await {
        Ok(repo) => repo,
        Err(err) => {
            warn!("Failed to initialise PGML repository: {}", err);
            None
        }
    };

    if pgml_repository.is_none() {
        warn!("PGML Admin dashboard disabled: DATABASE_URL is not configured");
    }
    let pgml_repository = web::Data::new(pgml_repository);

    //初始化模型
    let mut num_instances = 1; // 根據資源設定

    if let Some(value) = matches.get_one::<usize>("instances") {
        num_instances = *value;
    }
    let model_name = matches.get_one::<String>("model_name").unwrap();

    // Text type LLM
    let mut llm_recipients = HashMap::<String, Vec<Recipient<ProcessMessages>>>::new();
    let mut audio_recipients = HashMap::<String, Vec<Recipient<ProcessAudio>>>::new();
    let mut shutdown_recipients = Vec::new();

    let model_config_table = load_model_configs()?;

    for _ in 0..num_instances {
        if let Some(config) = model_config_table.get(model_name) {
            if config.model_type == llmserver_rs::utils::ModelType::LLM {
                let llm = llmserver_rs::llm::simple::SimpleRkLLM::init(&config);
                let model_name = config.model_name.clone();

                let addr = llm.unwrap().start(); // 啟動 Actor，一次即可
                if let Some(vec) = llm_recipients.get_mut(&model_name) {
                    vec.push(addr.clone().recipient::<ProcessMessages>());
                } else {
                    llm_recipients.insert(
                        model_name,
                        vec![addr.clone().recipient::<ProcessMessages>()],
                    );
                }
                shutdown_recipients.push(addr.clone().recipient::<ShutdownMessages>());
            } else if config.model_type == llmserver_rs::utils::ModelType::ASR {
                let (llm, modelname) = match (*model_name).as_str() {
                    "happyme531/SenseVoiceSmall-RKNN2" => {
                        let config_path = "assets/config/sensevoicesmall.json";
                        let file = File::open(config_path)
                            .expect(&format!("Config {} not found!", config_path));
                        let mut de = serde_json::Deserializer::from_reader(BufReader::new(file));
                        let config = SimpleASRConfig::deserialize(&mut de)?;
                        (
                            llmserver_rs::asr::simple::SimpleASR::init(&config),
                            config.model_name.clone(),
                        )
                    }
                    _ => {
                        continue;
                    }
                };
                let addr = llm.unwrap().start(); // 啟動 Actor，一次即可
                if let Some(vec) = audio_recipients.get_mut(&modelname) {
                    vec.push(addr.clone().recipient::<ProcessAudio>());
                } else {
                    audio_recipients
                        .insert(modelname, vec![addr.clone().recipient::<ProcessAudio>()]);
                }
                shutdown_recipients.push(addr.clone().recipient::<ShutdownMessages>());
            }
        } else {
            panic!("Model {} not found in the configuration!", model_name);
        }
    }

    if audio_recipients.len() == 0 && llm_recipients.len() == 0 {
        panic!("You do not load any model");
    }

    let bind_address =
        std::env::var("LLMSERVER_BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8443".to_string());

    HttpServer::new(move || {
        let pgml_repository = pgml_repository.clone();
        let (app, api) = App::new()
            .app_data(web::Data::new(llm_recipients.clone()))
            .app_data(web::Data::new(audio_recipients.clone()))
            .app_data(pgml_repository.clone())
            .into_utoipa_app()
            .map(|app| app.wrap(Logger::default()))
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
            .service(
                scope::scope("/admin/api")
                    .service(admin::list_models)
                    .service(admin::register_model)
                    .service(admin::delete_model),
            )
            .service(web::resource("/admin").route(web::get().to(admin::dashboard)))
            .service(health)
            .service(Files::new("/admin", "./assets/admin").index_file("index.html"))
    })
    .bind((Ipv4Addr::UNSPECIFIED, 8443))?
    .run()
    .await?;

    Ok(())
}
