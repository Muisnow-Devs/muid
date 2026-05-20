package grpcutils

import (
	"google.golang.org/grpc"

	"sanzi.io/muid/pkg/log"
)

// TraceUnaryInterceptor injects trace id into request context (see pkg/log).
var TraceUnaryInterceptor grpc.UnaryServerInterceptor = log.UnaryServerInterceptor()
