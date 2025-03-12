# llmserver-rs

A Rust-based, OpenAI-style API server for large language models (LLMs) that can run on the Orange Pi 5.

## Description

This project provides a Rust implementation of an API server that mimics the functionality of OpenAI's LLM API. It allows users to interact with large language models directly from their applications, leveraging the performance and safety of Rust.

## Features

- **OpenAI-style API**: Compatible with OpenAI's API endpoints for easy integration.
- **Rust Language**: Utilizes Rust for its performance, safety, and concurrency features.
- **Hardware Compatibility**: Specifically designed to run on the Orange Pi 5, powered by the rk3588 chip.

## Installation

To install and run `llmserver-rs`, follow these steps:

1. **Clone the Repository**:
```bash
git clone https://github.com/darkautism/llmserver-rs
```
Build the Project:
```bash
cd llmserver-rs
cargo build --release
```
Run the Server:
```bash
./target/release/llmserver kautism/DeepSeek-R1-Distill-Qwen-1.5B-RK3588S-RKLLM1.1.4
```

## Support module

This llmserver now only support these modules

| Model name | Size | Mem useage (Estimated) |
| --- | --- |
| [kautism/DeepSeek-R1-Distill-Qwen-1.5B-RK3588S-RKLLM1.1.4](https://huggingface.co/kautism/DeepSeek-R1-Distill-Qwen-1.5B-RK3588S-RKLLM1.1.4) | 2.04GB | 2.07 GB |


## Usage

You can access the online documentation at http://localhost:8080/swagger-ui/, which includes request examples and curl demo code.

The API server provides the following endpoints:

- /v1/completions: Generate text completions based on a given prompt.
- /v1/chat/completions: Generate chat completions for conversational AI.


## License
This project is licensed under the MIT License.

## Acknowledgements

[OpenAI](https://platform.openai.com/docs/api-reference) for their pioneering work in LLM APIs.

[Orange Pi 5](http://www.orangepi.org/) for providing the hardware platform.