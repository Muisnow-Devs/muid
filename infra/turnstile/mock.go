package turnstile

import "context"

// MockVerifier is a Verifier test double. It returns Err when set, otherwise
// Result. When neither is set it returns a successful result.
type MockVerifier struct {
	Result Result
	Err    error
}

// AlwaysValid returns a MockVerifier that approves every token.
func AlwaysValid() *MockVerifier {
	return &MockVerifier{Result: Result{Success: true}}
}

// AlwaysInvalid returns a MockVerifier that rejects every token.
func AlwaysInvalid() *MockVerifier {
	return &MockVerifier{Result: Result{Success: false, ErrorCodes: []string{"invalid-input-response"}}}
}

// Verify implements Verifier.
func (m *MockVerifier) Verify(_ context.Context, token, _ string) (Result, error) {
	if m.Err != nil {
		return Result{}, m.Err
	}
	if token == "" {
		return Result{}, ErrMissingToken
	}
	return m.Result, nil
}
