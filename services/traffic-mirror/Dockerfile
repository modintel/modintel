FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY . .

RUN go mod download
RUN go build -o traffic-mirror .

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/traffic-mirror .

EXPOSE 8080

CMD ["./traffic-mirror"]
