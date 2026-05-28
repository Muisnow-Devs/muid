package grpcutils

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"buf.build/go/protovalidate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"sanzi.io/muid/pkg/log"
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
			log.LogUnexpected(
				ctx,
				"protovalidate: request is not proto.Message",
				fmt.Sprintf("type: %T", req),
			)
			return nil, status.Errorf(codes.Internal, "internal error")
		}
		if err := v.Validate(msg); err != nil {
			var valErr *protovalidate.ValidationError
			if errors.As(err, &valErr) {
				log.Logger(ctx).Info("invalid_argument",
					slog.String("reason", "protovalidate"),
					slog.String("method", info.FullMethod),
					slog.String("detail", valErr.Error()),
				)
				return nil, status.Error(codes.InvalidArgument, clientValidationMessage)
			}
			log.LogUnexpected(
				ctx,
				"protovalidate",
				err.Error(),
				slog.String("method", info.FullMethod),
			)
			return nil, status.Error(codes.Internal, "internal error")
		}
		return handler(ctx, req)
	}, nil
}
