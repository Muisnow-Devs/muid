package grpcutils

import (
	"google.golang.org/grpc"

	"sanzi.io/muid/pkg/traceid"
)

// TraceUnaryInterceptor injects trace id into request context (see pkg/traceid).
var TraceUnaryInterceptor grpc.UnaryServerInterceptor = traceid.UnaryServerInterceptor()
