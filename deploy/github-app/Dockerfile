FROM rust:1.90-slim-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin cargoscope --bin cargoscope-bot

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/cargoscope /usr/local/bin/cargoscope
COPY --from=builder /src/target/release/cargoscope-bot /usr/local/bin/cargoscope-bot
ENV CARGOSCOPE_BOT_LISTEN=0.0.0.0:8080 \
    CARGOSCOPE_BOT_WORK_DIR=/data \
    CARGOSCOPE_BOT_STATE=/data/state.json
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["cargoscope-bot", "serve"]
