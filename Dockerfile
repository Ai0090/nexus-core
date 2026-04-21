FROM rust:1.86-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release --bin TET-Core

FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/TET-Core /usr/local/bin/TET-Core
EXPOSE 5010
ENV TET_REST_BIND=0.0.0.0:5010
CMD ["TET-Core"]

