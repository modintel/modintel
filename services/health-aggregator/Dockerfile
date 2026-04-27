FROM golang:1.25-alpine
ENV GOPROXY=https://goproxy.io,https://goproxy.cn,https://proxy.golang.org,direct

WORKDIR /app
RUN apk add --no-cache git

COPY go.mod ./
RUN for i in $(seq 1 15); do \
    go mod download -x && break || \
    (echo "Retry $i..." && sleep 20); \
    if [ $i -eq 15 ]; then exit 1; fi; \
    done

COPY . .
RUN go build -v -o health-aggregator .

EXPOSE 8090

CMD ["./health-aggregator"]
