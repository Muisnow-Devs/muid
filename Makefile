.PHONY: all build clean authn authz profile gateway mailer

# Output directory for binaries
BIN_DIR := bin
GO_CC := go
GO_ENV := CGO_ENABLED=0 GOOS=linux GOARCH=amd64

# List of services to build
SERVICES := authn authz profile gateway mailer

PROTO_DIR := ./api/proto
PROTO_FILES := $(shell find $(PROTO_DIR) -name "*.proto")
PROTO_STAMP := .proto_stamp

all: build

# Build all services
build: $(SERVICES)

# Build individual services
$(SERVICES): proto
	@echo "Building $@..."
	@mkdir -p $(BIN_DIR)
	$(GO_ENV) go build -o $(BIN_DIR)/$@ ./cmd/$@

# Generate protobuf files
$(PROTO_STAMP): $(PROTO_FILES)
	protoc \
		--go_out=. \
		--go-grpc_out=. \
		--go_opt=module=sanzi.io/muid \
		--go-grpc_opt=module=sanzi.io/muid \
		-I $(PROTO_DIR) \
		$(PROTO_FILES)
	touch $(PROTO_STAMP)

proto: $(PROTO_STAMP)

# Clean build artifacts
clean: clean-bin clean-protos
clean-bin:
	@echo "Cleaning binaries..."
	rm -rf $(BIN_DIR)

clean-protos:
	@echo "Cleaning generated protobuf files..."
	find . -type f -name "*.pb.go" -delete
	rm -f .proto_stamp