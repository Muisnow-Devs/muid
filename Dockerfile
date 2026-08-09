FROM golang:1.26.5 AS builder

ARG BUF_VERSION=1.69.0
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        make \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
        amd64) buf_arch="x86_64" ;; \
        arm64) buf_arch="aarch64" ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -sSL \
        "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-${buf_arch}" \
        -o /usr/local/bin/buf \
    && chmod +x /usr/local/bin/buf

COPY . .

# Required checks run before the image build.
RUN if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
        rm -rf .git \
        && git init \
        && git add --all; \
    fi \
    && make check

# Build all services.
RUN make TARGETOS="${TARGETOS}" TARGETARCH="${TARGETARCH}" build

FROM golang:1.26.5 AS dev

WORKDIR /app
COPY . .

RUN go install github.com/cosmtrek/air@latest

CMD ["air"]

# minimal runtime
FROM gcr.io/distroless/base-debian13

COPY --from=builder /app/bin/authn /authn
COPY --from=builder /app/bin/authz /authz
COPY --from=builder /app/bin/profile /profile
COPY --from=builder /app/bin/gateway-public /gateway-public
COPY --from=builder /app/bin/gateway-services /gateway-services
COPY --from=builder /app/bin/gateway-internal /gateway-internal
COPY --from=builder /app/bin/mailer /mailer
