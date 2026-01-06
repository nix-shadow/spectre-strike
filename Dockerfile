FROM golang:1.24-alpine AS builder

WORKDIR /build

RUN apk add --no-cache git make

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o attack ./cmd/main.go

FROM alpine:latest

RUN apk add --no-cache ca-certificates python3 bash

WORKDIR /app

COPY --from=builder /build/attack .
COPY --from=builder /build/launcher.py .
COPY --from=builder /build/launcher.sh .
COPY --from=builder /build/configs ./configs
COPY --from=builder /build/wordlists ./wordlists

RUN chmod +x attack launcher.py launcher.sh

ENV PATH="/app:${PATH}"

ENTRYPOINT ["python3", "launcher.py"]
