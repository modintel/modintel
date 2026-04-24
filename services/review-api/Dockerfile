FROM golang:1.26-alpine
ENV GOPROXY=https://goproxy.io,https://goproxy.cn,https://proxy.golang.org,direct
ENV GOWORK=off

WORKDIR /app

RUN apk add --no-cache git

# Copy module files first for layer caching
COPY go.mod go.sum ./

RUN for i in $(seq 1 15); do \
    go mod download && break || \
    (echo "Retry $i..." && sleep 20); \
    if [ $i -eq 15 ]; then exit 1; fi; \
    done

# Copy source
COPY . .

RUN go build -v -o /app/review-api .

EXPOSE 8082

CMD ["/app/review-api"]
