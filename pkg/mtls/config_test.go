package mtls_test

import (
	"errors"
	"testing"

	"sanzi.io/muid/pkg/mtls"
)

func TestValidatePathGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		required bool
		paths    []string
		wantErr  error
	}{
		{name: "optional omitted", paths: []string{"", "", ""}},
		{name: "complete", required: true, paths: []string{"cert", "key", "roots"}},
		{name: "partial", paths: []string{"cert", "", "roots"}, wantErr: mtls.ErrPartialPathGroup},
		{name: "required omitted", required: true, paths: []string{"", "", ""}, wantErr: mtls.ErrRequiredPathGroup},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := mtls.ValidatePathGroup(test.required, test.paths...)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("ValidatePathGroup() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}
