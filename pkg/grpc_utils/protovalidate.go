package grpcutils

import (
	"sync"

	"buf.build/go/protovalidate"
)

var (
	protovalidateOnce      sync.Once
	protovalidateSingleton protovalidate.Validator
	protovalidateInitErr   error
)

// ProtovalidateValidator returns a process-wide [protovalidate.Validator] (lazy init).
// Pass the result to [protovalidate.UnaryServerInterceptor] from
// github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/protovalidate.
func ProtovalidateValidator() (protovalidate.Validator, error) {
	protovalidateOnce.Do(func() {
		protovalidateSingleton, protovalidateInitErr = protovalidate.New()
	})
	return protovalidateSingleton, protovalidateInitErr
}
