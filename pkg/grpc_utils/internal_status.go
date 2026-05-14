package grpcutils

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GRPCInternalError is a generic, client-safe internal failure.
func GRPCInternalError() error {
	return status.Error(codes.Internal, "internal error")
}
