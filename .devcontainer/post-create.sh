#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# post-create.sh  –  runs once after the dev container is first created.
#
# Actions
#   1. Download Go module dependencies
#   2. Verify buf toolchain
#   3. Print a helpful "what's next" banner
# ---------------------------------------------------------------------------
set -euo pipefail

echo ""
echo "══════════════════════════════════════════════════"
echo "  muid dev-container — post-create setup"
echo "══════════════════════════════════════════════════"

# ── 1. Go module dependencies ───────────────────────────────────────────────
echo ""
echo "▸ Downloading Go module dependencies …"
go mod download

echo "▸ Downloading Go workspace dependencies …"
go work sync 2>/dev/null || true   # best-effort; workspace may not need it

# ── 2. Buf ──────────────────────────────────────────────────────────────────
echo ""
echo "▸ Verifying buf installation …"
buf --version

echo "▸ Updating buf dependencies …"
buf dep update 2>/dev/null || true  # non-fatal; remote plugins don't need local deps

# ── 3. Banner ───────────────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════"
echo "  ✓ Dev-container ready!"
echo ""
echo "  Useful commands:"
echo "    buf build                        # validate proto files"
echo "    buf generate --template buf.gen.yaml  # regenerate gRPC stubs"
echo "    go generate ./internal/authn/ent/..."
echo "    go generate ./internal/profile/ent/..."
echo "    go build ./cmd/authn"
echo "    go build ./cmd/profile"
echo "    go build ./cmd/mailer"
echo "    go test ./..."
echo ""
echo "  Infra endpoints (inside compose network):"
echo "    PostgreSQL  postgres:5432"
echo "    NATS        nats:4222  (monitoring: nats:8222)"
echo "    Redis       redis:6379"
echo "══════════════════════════════════════════════════"
