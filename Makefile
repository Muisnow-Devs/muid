.PHONY: all build check clean clean-bin clean-generated authn authz profile gateway-public gateway-services gateway-internal mailer test-publish-tools proto graphql generate generate-check

# Output directory for binaries
BIN_DIR := bin
GO_CC := GOWORK=off go
TARGETOS ?= linux
TARGETARCH ?= amd64
GO_ENV := GOWORK=off CGO_ENABLED=0 GOOS=$(TARGETOS) GOARCH=$(TARGETARCH)

# List of services to build
SERVICES := authn authz profile gateway-public gateway-services gateway-internal mailer

# NATS publishers for manual mailer testing (native GOOS/GOARCH)
TEST_PUBLISH_TOOLS := test-publish-otp test-publish-login-alert test-publish-email-changed test-publish-passkey-added

# Generated artifacts checked into the repository.
GENERATED_PATHS := \
	':(glob)api/**/*.pb.go' \
	internal/gatewaypublic/graph/generated/generated.go \
	internal/gatewaypublic/graph/model/models_gen.go \
	':(glob)internal/gatewaypublic/graph/*.resolvers.go'

all: build

# Build all services
build: $(SERVICES)

# Build individual services
$(SERVICES):
	@echo "Building $@..."
	@mkdir -p $(BIN_DIR)
	$(GO_ENV) go build -o $(BIN_DIR)/$@ ./cmd/$@

# Generate protobuf files
proto:
	buf build
	buf generate --template buf.gen.yaml

# Generate the public GraphQL server with the gqlgen version pinned in go.mod.
graphql:
	cd internal/gatewaypublic && $(GO_CC) tool gqlgen generate

generate: proto graphql

# Regenerate and fail when tracked or new generated artifacts are not committed.
generate-check: generate
	git diff --exit-code -- $(GENERATED_PATHS)
	@untracked="$$(git ls-files --others --exclude-standard -- $(GENERATED_PATHS))"; \
	if [ -n "$$untracked" ]; then \
		echo "Untracked generated artifacts:"; \
		echo "$$untracked"; \
		exit 1; \
	fi

# Required repository check: generated artifacts must be current before tests.
check: generate-check
	$(GO_CC) test ./...

# Build mailer NATS test publishers (host platform)
test-publish-tools: $(TEST_PUBLISH_TOOLS)

$(TEST_PUBLISH_TOOLS):
	@echo "Building $@..."
	@mkdir -p $(BIN_DIR)
	$(GO_CC) build -o $(BIN_DIR)/$@ ./cmd/test/$@

# Clean build artifacts. Checked-in generated sources are intentionally kept.
clean: clean-bin
clean-bin:
	@echo "Cleaning binaries..."
	rm -rf $(BIN_DIR)

# Explicit, opt-in removal for callers that intend to regenerate immediately.
clean-generated:
	@echo "Cleaning generated protobuf files..."
	find api/proto -type f -name "*.pb.go" -delete
