package grpcutils

import (
	"context"
	"errors"
	"log"
	"sync"

	"buf.build/go/protovalidate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"sanzi.io/muid/pkg/traceid"
)

var (
	protovalidateOnce      sync.Once
	protovalidateSingleton protovalidate.Validator
	protovalidateInitErr   error
)

// ProtovalidateValidator returns a process-wide [protovalidate.Validator] (lazy init).
func ProtovalidateValidator() (protovalidate.Validator, error) {
	protovalidateOnce.Do(func() {
		protovalidateSingleton, protovalidateInitErr = protovalidate.New()
	})
	return protovalidateSingleton, protovalidateInitErr
}

const clientValidationMessage = "request validation failed"

// UnaryProtovalidateInterceptor validates unary RPC requests using buf validate / protovalidate.
// On rule violations it returns [codes.InvalidArgument] with a fixed client-safe message,
// logs violation text with trace_id, and omits structured violation details from the status.
func UnaryProtovalidateInterceptor() (grpc.UnaryServerInterceptor, error) {
	v, err := ProtovalidateValidator()
	if err != nil {
		return nil, err
	}
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		msg, ok := req.(proto.Message)
		if !ok {
			return nil, status.Errorf(codes.Internal, "unsupported request type")
		}
		if err := v.Validate(msg); err != nil {
			tid, _ := traceid.FromContext(ctx)
			if tid == "" {
				tid = "none"
			}
			var valErr *protovalidate.ValidationError
			if errors.As(err, &valErr) {
				log.Printf(
					"invalid_argument trace_id=%s method=%s reason=protovalidate detail=%s",
					tid,
					info.FullMethod,
					valErr.Error(),
				)
				return nil, status.Error(codes.InvalidArgument, clientValidationMessage)
			}
			traceid.LogUnexpected(ctx, "protovalidate", err.Error(), "method", info.FullMethod)
			return nil, status.Error(codes.Internal, "internal error")
		}
		return handler(ctx, req)
	}, nil
}
