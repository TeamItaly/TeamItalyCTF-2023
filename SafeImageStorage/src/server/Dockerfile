FROM golang:1.21

WORKDIR /src
COPY go.mod go.sum main.go ./

RUN go build -ldflags="-w" -o server .

CMD ["/src/server"]