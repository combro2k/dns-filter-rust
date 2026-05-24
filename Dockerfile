# syntax=docker/dockerfile:1

FROM rust:1.85-alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY templates ./templates
COPY migrations ./migrations

RUN cargo build --release --locked

FROM alpine:3.20

RUN apk add --no-cache ca-certificates \
    && adduser -D -u 65534 dns-filter

WORKDIR /app

COPY --from=builder /build/target/release/dns-filter /usr/local/bin/dns-filter
COPY docker/config.yaml /etc/dns-filter/config.yaml

RUN mkdir -p /app/data /app/run \
    && chown -R dns-filter:dns-filter /app /etc/dns-filter

EXPOSE 53/udp 53/tcp 8080/tcp 9100/tcp

USER dns-filter

ENTRYPOINT ["/usr/local/bin/dns-filter"]
CMD ["start", "--config", "/etc/dns-filter/config.yaml"]
