FROM rust:1.87 AS build
USER root
RUN cargo build --release

FROM debian:bookworm-slim
USER root
CMD ["/app"]
