FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -o waf-blocker .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /build/waf-blocker /usr/local/bin/waf-blocker
EXPOSE 8086
ENTRYPOINT ["waf-blocker"]
