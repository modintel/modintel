FROM caddy:2-builder AS build

RUN xcaddy build \
    --with github.com/dotvezz/caddy-mirror@v0.0.8

FROM caddy:2-alpine

COPY --from=build /usr/bin/caddy /usr/bin/caddy

EXPOSE 8080

CMD ["caddy", "run"]
