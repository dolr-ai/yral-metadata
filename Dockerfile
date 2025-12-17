FROM scratch

WORKDIR /app

COPY ./target/x86_64-unknown-linux-musl/release/yral-metadata-server .
COPY ./config.toml .

ENV RUST_LOG="debug"
ENV BIND_ADDRESS="0.0.0.0:3000"
EXPOSE 3000

CMD ["./yral-metadata-server"]