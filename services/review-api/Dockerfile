FROM golang:1.26-alpine

RUN apk add --no-cache docker-cli docker-compose

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o review-api .

EXPOSE 8082

CMD ["./review-api"]
