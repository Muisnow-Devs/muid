# Reachable Go Dependency Vulnerabilities

Status: Implemented

Classification: B (dependency/runtime behavior)

# Problem

The compiled services use dependency and standard-library versions with known,
reachable vulnerabilities.

# Evidence

- Root `go.mod` declares Go 1.26.2, `google.golang.org/grpc` 1.81.1,
  `golang.org/x/image` 0.41.0, and `golang.org/x/text` 0.37.0.
- `api/go.mod` independently pins `google.golang.org/grpc` 1.81.1.
- `govulncheck ./...` from the merged gateway tree reported 13 reachable
  vulnerabilities, including GO-2026-6061 in gRPC and standard-library issues
  fixed after Go 1.26.2.

# Current Design

The root and replaced `./api` modules now use Go 1.26.5 and gRPC 1.82.1. The
root module uses `golang.org/x/image` 0.43.0 and `golang.org/x/text` 0.39.0.
Container and development images also use Go 1.26.5. Vulnerability scanning is
an explicit root/API acceptance command rather than part of `make check`.

# Why This Is a Problem

Reachability means application call paths can invoke affected symbols. Updating
only one module can also leave generated API consumers on a vulnerable or
incompatible version.

# Proposed Design

Implemented with Go 1.26.5, gRPC 1.82.1 in both modules, `x/text` 0.39.0, and
`x/image` 0.43.0. Related module graphs and checksums were tidied; protobuf
runtime versions remain aligned with the pinned generators.

# Proposed API / Protocol Changes

No intended API change. Regenerated protobuf stubs must remain compatible with
the selected gRPC runtime.

# Dependency / Flow Changes

The toolchain and module graph move to fixed versions. No service dependency
edge changes.

# Security Implications

Finding classification: `Confirmed Vulnerability`.

- Threat: exploitation of reachable vulnerable library or standard-library
  behavior.
- Precondition: attacker reaches an affected service path.
- Boundary: public/internal network input into Go runtimes.
- Impact: depends on the individual advisories; `govulncheck` proves affected
  symbols are reachable.
- Existing protection: application validation and gateway controls reduce some
  inputs but do not correct vulnerable library behavior.
- Correction: upgrade all affected modules and runtime, then rescan.

# Affected Code

- `go.mod`, `go.sum`
- `api/go.mod`, `api/go.sum`
- `Dockerfile`, `.devcontainer/Dockerfile`

# Implementation Steps

1. Updated the Go directive and container toolchains to 1.26.5.
2. Upgraded gRPC in both modules and upgraded `x/text` and `x/image`.
3. Tidied the root and API module graphs and reviewed transitive changes.
4. Checked generated output through the pinned generation workflow.
5. Scanned the root and API modules independently.

# Validation Criteria

- Root `govulncheck ./...` and `cd api && govulncheck ./...` reported no
  reachable known vulnerability.
- `make check`, full Go tests, `go vet ./...`, and `go build ./...` passed.
- Gateway race validation passed 152 tests across 20 packages.
- Root and API modules resolve the same gRPC 1.82.1 runtime.
