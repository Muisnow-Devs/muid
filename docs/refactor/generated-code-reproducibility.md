# Generated-Code Reproducibility

Status: Implemented

Classification: S (tooling and artifact ownership)

# Problem

Protobuf and GraphQL generated files cannot be deterministically reproduced by
one pinned repository workflow. The documented gqlgen invocation depends on
undeclared tool dependencies, and Buf plugin versions are not locked tightly
enough to prevent generated comment/version drift.

# Evidence

- `Makefile:proto` runs `buf build` and `buf generate --template buf.gen.yaml`
  but has no GraphQL generation or drift check.
- `buf.gen.yaml` defines the protobuf generation plugins used for checked-in
  `api/**/*.pb.go` and `*_grpc.pb.go`.
- `internal/gatewaypublic/gqlgen.yml` documents
  `go run github.com/99designs/gqlgen generate` from its directory.
- Running that documented command on the merged tree initially failed because
  gqlgen tool dependencies were absent from `go.sum`; `-mod=mod` succeeded but
  produced resolver signature/import drift.
- Local Buf generation also produced tool-version comment drift in generated
  gRPC stubs.

# Current Design

Generated artifacts are committed and reproduced through pinned repository
targets. Buf 1.69.0 is pinned in container tooling, remote Go/grpc plugins are
pinned in `buf.gen.yaml`, and gqlgen is a Go tool dependency invoked with
`GOWORK=off go tool gqlgen`.

# Why This Is a Problem

Protocol changes cannot be reviewed reliably when tool drift is mixed with
semantic changes. A clean checkout may be unable to run the stated generator,
and CI cannot prove that generated code is current.

# Proposed Design

Implemented `make generate`, `make generate-check`, and `make check`.
`generate-check` regenerates protobuf/GraphQL artifacts, rejects tracked drift,
and rejects untracked files within the declared generated paths. `make check`
runs that gate before the full Go test suite.

# Proposed API / Protocol Changes

No runtime protocol change. Generated Go output remains checked in. Tool version
changes are reviewed as explicit dependency updates.

# Dependency / Flow Changes

`make generate` runs Buf build/generation and gqlgen. `make generated-check`
checks the explicit generated path set against Git. Docker builds run
`make check`; when the build context has no `.git`, the builder creates a
temporary initialized/staged Git baseline so the same drift gate remains
meaningful.

# Security Implications

Pinned generators reduce supply-chain ambiguity. Use versioned modules/plugins
with checksums; do not download unversioned `latest` executables in CI.

# Affected Code

- `buf.gen.yaml`, root `Makefile`
- root `go.mod`, `go.sum` tool dependency declaration
- `internal/gatewaypublic/gqlgen.yml`
- generated files under `api/` and `internal/gatewaypublic/graph/generated`
- `Dockerfile`, `.devcontainer/Dockerfile`

# Implementation Steps

1. Pinned Buf 1.69.0 and multi-architecture amd64/arm64 downloads in Docker and
   devcontainer builds.
2. Pinned protoc Go 1.36.11 revision 1 and protoc gRPC 1.6.2 revision 1 in Buf.
3. Declared gqlgen in the Go tool block and normalized gqlgen output paths.
4. Added generate, drift-check, and required repository check targets.
5. Made Docker run the check with a real or temporary Git baseline and build all
   seven binaries for `TARGETOS`/`TARGETARCH`.

# Validation Criteria

- `make check` regenerated all artifacts without tracked/untracked drift and ran
  the full Go test suite.
- Docker/devcontainer tool downloads support amd64 and arm64 and reject unknown
  architectures.
- Full Go tests, gateway race tests (152/20), vet, build, and root/API
  vulnerability scans passed.
