FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig make

WORKDIR /app
COPY . .

RUN cargo build --release --bin gatee && \
    strip target/release/gatee

FROM alpine:3.22

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -h /data gatee

COPY --from=builder /app/target/release/gatee /usr/local/bin/gatee

ENV GATEE_LISTEN=0.0.0.0:7890
ENV GATEE_DB=/data/gatee.db
ENV APP_TIMEZONE=Asia/Jakarta

USER gatee
WORKDIR /data
VOLUME ["/data"]
EXPOSE 7890
ENTRYPOINT ["gatee"]
