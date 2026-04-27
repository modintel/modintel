FROM golang:1.25-alpine AS builder
ENV GOPROXY=https://goproxy.io,https://goproxy.cn,https://proxy.golang.org,direct

WORKDIR /app
RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN for i in $(seq 1 15); do \
    go mod download -x && break || \
    (echo "Retry $i..." && sleep 20); \
    if [ $i -eq 15 ]; then exit 1; fi; \
    done

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -v -o log-collector .

FROM alpine:3.19

WORKDIR /app

COPY --from=builder /app/log-collector /app/log-collector

CMD ["/app/log-collector"]