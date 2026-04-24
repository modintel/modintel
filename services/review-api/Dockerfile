FROM golang:1.25-alpine
ENV GOPROXY=https://goproxy.io,https://goproxy.cn,https://proxy.golang.org,direct
ENV GOWORK=off

WORKDIR /app

RUN apk add --no-cache git

# Copy root go.mod (for the shared pkg module)
COPY go.mod ./

# Copy shared packages source
COPY pkg/ ./pkg/

# Copy service module files
COPY services/review-api/go.mod services/review-api/go.sum ./services/review-api/

WORKDIR /app/services/review-api
RUN for i in $(seq 1 15); do \
    go mod download -x && break || \
    (echo "Retry $i..." && sleep 20); \
    if [ $i -eq 15 ]; then exit 1; fi; \
    done

# Copy service source
COPY services/review-api/ ./

# Update go.sum with transitive deps from replaced modintel module
RUN go mod tidy

RUN go build -v -o /app/review-api .

EXPOSE 8082

CMD ["/app/review-api"]
