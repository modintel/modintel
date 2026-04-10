FROM golang:1.21-alpine AS build

RUN apk add --no-cache git

ENV HOME=/root
RUN git clone https://github.com/caddyserver/xcaddy.git /tmp/xcaddy && \
    cd /tmp/xcaddy && \
    go build -o xcaddy . && \
    chmod +x xcaddy && \
    mv xcaddy /usr/local/bin/ && \
    xcaddy build v2.11.2 \
        --with github.com/dotvezz/caddy-mirror@v0.0.8

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

COPY --from=build /usr/bin/caddy /usr/bin/caddy

EXPOSE 8080

CMD ["caddy", "run"]
