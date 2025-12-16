# 1. Get Certificates
FROM alpine:latest as certs
RUN apk --update add ca-certificates

# 2. Final Image
FROM scratch
WORKDIR /app
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY ./target/x86_64-unknown-linux-musl/release/yral-metadata-server .
COPY ./config.toml .

ENV RUST_LOG="debug"
ENV BIND_ADDRESS="0.0.0.0:8080"
EXPOSE 8080

CMD ["./yral-metadata-server"]