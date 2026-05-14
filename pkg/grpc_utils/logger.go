package grpcutils

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"

	"sanzi.io/muid/pkg/traceid"
)

func LoggerInterceptor(
	ctx context.Context,
	req any,
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (any, error) {
	start := time.Now()

	resp, err := handler(ctx, req)

	tid, _ := traceid.FromContext(ctx)
	if tid == "" {
		tid = "none"
	}
	log.Printf(
		"method=%s trace_id=%s duration=%s err=%v",
		info.FullMethod,
		tid,
		time.Since(start),
		err,
	)

	return resp, err
}
