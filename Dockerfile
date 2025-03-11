FROM rust:alpine
WORKDIR /llmserver-rs
COPY . /llmserver-rs
#RUN apt update
#RUN apt install clang -y
#RUN wget https://github.com/airockchip/rknn-llm/raw/refs/heads/main/rkllm-runtime/Linux/librkllm_api/aarch64/librkllmrt.so -O /lib/librkllmrt.so
RUN apk add clang-dev openssl-dev curl
RUN cargo build --release
#RUN apt remove clang -y
#RUN rm -rf /var/lib/apt/lists/*

FROM alpine
WORKDIR /app
COPY --from=0 /llmserver-rs/target/release/llmserver-rs /app/llmserver-rs
COPY ./assets /app/assets
RUN rm -rf /llmserver-rs
ENTRYPOINT ["/app/llmserver-rs"]