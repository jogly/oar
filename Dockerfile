# Build command for image oauth-router:latest:
# docker build -t oauth-router:latest .

FROM golang:1.16-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .

RUN go build -o /app/bin/ ./cmd/server

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/bin/ /app/bin/

CMD ["/app/bin/server"]