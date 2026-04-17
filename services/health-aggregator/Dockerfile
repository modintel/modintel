FROM golang:1.26-alpine

WORKDIR /app

COPY go.mod ./
RUN go mod download

COPY . .
RUN go build -o health-aggregator .

EXPOSE 8090

CMD ["./health-aggregator"]
