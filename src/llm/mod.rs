use std::pin::Pin;

use crate::chat::Message;
use actix::{Actor, Handler};
pub use rkllm_rs::prelude::RkllmCallbackHandler;
use serde::de::DeserializeOwned;

pub mod simple;

pub trait AIModel {
    type Config: DeserializeOwned;
    fn init(config: &Self::Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>>
    where
        Self: Sized;
}

#[derive(actix::Message)]
#[rtype(result = "Result<Pin<Box<dyn futures::Stream<Item = String> + Send + 'static>>, ()>")]
pub struct ProcessMessages {
    pub messages: Vec<Message>,
}

#[derive(actix::Message)]
#[rtype(result = "Result<(), ()>")]
pub struct ShutdownMessages ;


pub trait LLM: Actor + Handler<ProcessMessages> + Handler<ShutdownMessages> + AIModel{}
