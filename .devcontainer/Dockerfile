# ---------------------------------------------------------------------------
# muid dev-container image
#
# Based on the official Go 1.26 image (matches go.mod).
# Installs:
#   • Buf CLI          – protobuf build + codegen (buf build / buf generate)
#   • golangci-lint    – Go linting
#   • goimports        – import formatter (used by gopls)
#   • gofumpt          – stricter gofmt (used by gopls)
#   • air              – live-reload dev server
#   • goose (optional) – if you add SQL migrations later
#   • Common dev tools: git, curl, bash, make, jq
# ---------------------------------------------------------------------------
FROM golang:1.26.5-bookworm

ARG BUF_VERSION=1.69.0
ARG GOLANGCI_VERSION=2.1.6
ARG TARGETARCH=amd64

# ── System packages ─────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash \
        curl \
        git \
        gnupg \
        jq \
        make \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# ── Buf CLI ─────────────────────────────────────────────────────────────────
RUN case "${TARGETARCH}" in \
        amd64) buf_arch="x86_64" ;; \
        arm64) buf_arch="aarch64" ;; \
        *) echo "unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -sSL \
        "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-${buf_arch}" \
        -o /usr/local/bin/buf \
    && chmod +x /usr/local/bin/buf

# ── golangci-lint ────────────────────────────────────────────────────────────
RUN curl -sSfL \
        "https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh" \
    | sh -s -- -b /usr/local/bin "v${GOLANGCI_VERSION}"

# ── Go tools (installed into GOPATH) ─────────────────────────────────────────
# Use a throw-away module to avoid polluting the workspace go.sum.
RUN go install golang.org/x/tools/cmd/goimports@v0.33.0 \
    && go install mvdan.cc/gofumpt@v0.8.0 \
    && go install github.com/air-verse/air@v1.61.7 \
    && go install entgo.io/ent/cmd/ent@v0.14.6

# Make GOPATH/bin available everywhere
ENV PATH="${PATH}:/root/go/bin"

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /workspace
COPY go.mod go.sum ./
