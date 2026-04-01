FROM rust:1.87 AS build
USER root
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12@sha256:0123456789abcdef
USER nonroot
CMD ["/app"]
