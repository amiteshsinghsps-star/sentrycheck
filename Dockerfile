FROM rust:1.94.1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY kb ./kb
COPY frontend/template.html ./frontend/template.html
COPY scripts/update_kb.py ./scripts/update_kb.py
RUN cargo build --locked --release -p sentrycheck-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates runc strace skopeo python3 && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/sentrycheck /usr/local/bin/sentrycheck
WORKDIR /work
ENTRYPOINT ["sentrycheck"]
