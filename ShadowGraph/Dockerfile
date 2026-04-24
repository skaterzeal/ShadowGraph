# syntax=docker/dockerfile:1.7

# -------- Build stage --------
FROM golang:1.25-alpine AS builder

# Repro ve minimal boyut için build bayrakları
ENV CGO_ENABLED=0 \
    GO111MODULE=on \
    GOFLAGS="-trimpath"

WORKDIR /src

# Modülleri önce ekle — Docker cache verimliliği
COPY go.mod go.sum ./
RUN go mod download

# Kaynağı kopyala
COPY . .

# Statik binary — no-cgo, küçük ikili
ARG VERSION=dev
RUN go build \
    -ldflags="-s -w -X main.Version=${VERSION}" \
    -o /out/shadowgraph \
    ./main.go

# -------- Runtime stage --------
FROM alpine:3.20

# Ham socket gerektiren UDP/TCP taramaları için gerekli capabilities
# NET_RAW kullanıcıya docker run --cap-add=NET_RAW ile verilmelidir.
# Burada yalnızca minimal sertifika + timezone ekliyoruz.
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 -s /sbin/nologin shadow \
    && mkdir -p /data \
    && chown -R shadow:shadow /data

USER shadow
WORKDIR /data

COPY --from=builder --chown=shadow:shadow /out/shadowgraph /usr/local/bin/shadowgraph

# UI default port
EXPOSE 8080

# DB ve config /data altında kalıcı tutulur (volume mount önerilir)
VOLUME ["/data"]

ENTRYPOINT ["shadowgraph"]
CMD ["--help"]
