package oteltrace

// Config configures [NewTracer]. Environment mapping (when wired via envconfig):
//
//   - OTEL_SERVICE_NAME or per-service prefix + SERVICE_NAME
//   - OTEL_EXPORTER_OTLP_ENDPOINT
//   - OTEL_TRACES_EXPORTER: otlp | stdout | noop
//   - OTEL_ENABLED: when false, returns noop tracer
type Config struct {
	ServiceName string
	Enabled     bool
	Debug       bool
	// Exporter is one of: otlp, stdout, noop.
	Exporter string
	// OTLPEndpoint is the OTLP HTTP endpoint (e.g. from OTEL_EXPORTER_OTLP_ENDPOINT).
	OTLPEndpoint string
}
