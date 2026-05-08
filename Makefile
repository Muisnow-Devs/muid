.PHONY: all build clean authn authz profile gateway mailer

# Output directory for binaries
BIN_DIR := bin
GO_CC := go
GO_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# List of services to build
SERVICES := authn authz profile gateway mailer

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

# Clean build artifacts
clean: clean-bin clean-protos
clean-bin:
	@echo "Cleaning binaries..."
	rm -rf $(BIN_DIR)

clean-protos:
	@echo "Cleaning generated protobuf files..."
	find . -type f -name "*.pb.go" -delete