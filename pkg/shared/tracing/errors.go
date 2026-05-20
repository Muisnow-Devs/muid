package tracing

import "errors"

var (
	// ErrDisabled indicates tracing is turned off for this tracer instance.
	ErrDisabled = errors.New("trace: disabled")
	// ErrInvalidConfig indicates constructor config failed validation.
	ErrInvalidConfig = errors.New("trace: invalid config")
	// ErrExporterInit indicates the trace exporter could not be initialized.
	ErrExporterInit = errors.New("trace: exporter init failed")
)
