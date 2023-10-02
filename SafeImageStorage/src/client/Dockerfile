FROM golang:1.21

WORKDIR /src
COPY go.mod go.sum main.go ./

ENV GOOS js
ENV GOARCH wasm

RUN go build -ldflags="-w" -o client.wasm .
RUN cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .