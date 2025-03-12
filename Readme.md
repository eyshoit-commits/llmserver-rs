# llmserver-rs

A Rust-based, OpenAI-style API server for large language models (LLMs) that can run on the Orange Pi 5.

## Description

This project provides a Rust implementation of an API server that mimics the functionality of OpenAI's LLM API. It allows users to interact with large language models directly from their applications, leveraging the performance and safety of Rust.

## Features

- **OpenAI-style API**: Compatible with OpenAI's API endpoints for easy integration.
- **Rust Language**: Utilizes Rust for its performance, safety, and concurrency features.
- **Hardware Compatibility**: Specifically designed to run on the Orange Pi 5, powered by the rk3588 chip.

## Installation

You must need rknpu driver above 0.9.7.
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

## Install on cluster

You need to find out which sbc in your cluster is cpu rk3588

```bash
yourname@hostname$ microk8s kubectl get nodes
NAME                STATUS   ROLES    AGE     VERSION
kautism-desktop     Ready    <none>   16d     v1.32.2
kautism-orangepi5   Ready    <none>   6d16h   v1.32.2
```

Label your node
```bash
microk8s kubectl label nodes <node-name> cpu=rk3588
```

Apply your yaml, if you don't know how to write it, you can copy `k8s/*` as template

```bash
yourname@hostname$ microk8s kubectl apply -f k8s/deepseek-1.5b.yaml
persistentvolumeclaim/llmserver-pvc created
deployment.apps/llmserver created
service/llmserver-service created
```

**Note**: My yaml use rock-ceph as backend pvc provider. You can change it you liked. Or you can fellow [this guide](https://microk8s.io/docs/how-to-ceph) to build your own cluster storage system
**Note**: [error maybe happened](https://github.com/canonical/microk8s/issues/4314#issuecomment-1873823537)

Now you can see pod in your default namespace(if you do not like default namespace, change it by yourself).

```bash
sudo microk8s kubectl get all
NAME                                    READY   STATUS    RESTARTS      AGE
pod/llmserver-7bb666876d-9nzn6          1/1     Running   0             37s


NAME                        TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
service/llmserver-service   NodePort    10.152.183.39    <none>        80:31106/TCP   12m
```

Using any ip of your cluster node with node port to access your llm api

http://<your node ip not cluster ip>:31106/swagger-ui/

## Support module

This llmserver now only support these modules

| Model Name | Size | Mem useage (Estimated) | Microk8s config | Notes |
| --- | --- | --- | --- | --- |
| [kautism/DeepSeek-R1-Distill-Qwen-1.5B-RK3588S-RKLLM1.1.4](https://huggingface.co/kautism/DeepSeek-R1-Distill-Qwen-1.5B-RK3588S-RKLLM1.1.4) | 2.04GB | 2.07 GB | [link](k8s/simple.yaml) | |
| [kautism/kautism/DeepSeek-R1-Distill-Qwen-7B-RK3588S-RKLLM1.1.4](https://huggingface.co/kautism/kautism/DeepSeek-R1-Distill-Qwen-7B-RK3588S-RKLLM1.1.4) | 8.19GB | 9+ GB | [link](k8s/simple.yaml) | Only work on Opi 5 16 GB model|


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