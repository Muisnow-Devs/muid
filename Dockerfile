FROM golang:1.26.2 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y protobuf-compiler make

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

ENV PATH="$PATH:$(go env GOPATH)/bin"

COPY . .

# Build all services
RUN make build

FROM golang:1.26.2 AS dev

WORKDIR /app
COPY . .

RUN go install github.com/cosmtrek/air@latest

CMD ["air"]

# minimal runtime
FROM gcr.io/distroless/base-debian13

COPY --from=builder /bin/mailer /mailer
COPY --from=builder /bin/authn /authn
COPY --from=builder /bin/authz /authz
COPY --from=builder /bin/gateway /gateway