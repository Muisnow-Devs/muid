package account

import "errors"

var errProfileClientUnset = errors.New("authn: profile gRPC client is not configured")
