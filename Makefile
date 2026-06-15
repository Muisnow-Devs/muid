.PHONY: all build clean authn authz profile gateway-public gateway-services gateway-internal mailer test-publish-tools

# Output directory for binaries
BIN_DIR := bin
GO_CC := go
GO_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# List of services to build
SERVICES := authn authz profile gateway-public gateway-services gateway-internal mailer

# NATS publishers for manual mailer testing (native GOOS/GOARCH)
TEST_PUBLISH_TOOLS := test-publish-otp test-publish-login-alert test-publish-email-changed test-publish-passkey-added

all: build

# Build all services
build: $(SERVICES)

# Build individual services
$(SERVICES): proto
	@echo "Building $@..."
	@mkdir -p $(BIN_DIR)
	$(GO_ENV) go build -o $(BIN_DIR)/$@ ./cmd/$@

# Generate protobuf files
proto:
	buf build
	buf generate --template buf.gen.yaml

# Build mailer NATS test publishers (host platform)
test-publish-tools: $(TEST_PUBLISH_TOOLS)

$(TEST_PUBLISH_TOOLS):
	@echo "Building $@..."
	@mkdir -p $(BIN_DIR)
	$(GO_CC) build -o $(BIN_DIR)/$@ ./cmd/test/$@

# Clean build artifacts
clean: clean-bin clean-protos
clean-bin:
	@echo "Cleaning binaries..."
	rm -rf $(BIN_DIR)

clean-protos:
	@echo "Cleaning generated protobuf files..."
	find . -type f -name "*.pb.go" -delete