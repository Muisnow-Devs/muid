package tracing

type spanConfig struct {
	kind  SpanKind
	attrs []Attr
	debug bool
}

// SpanOption configures [Tracer.Start].
type SpanOption func(*spanConfig)

// WithSpanKind sets the span kind.
func WithSpanKind(kind SpanKind) SpanOption {
	return func(c *spanConfig) {
		c.kind = kind
	}
}

// WithAttributes attaches attributes at span start.
func WithAttributes(attrs ...Attr) SpanOption {
	return func(c *spanConfig) {
		c.attrs = append(c.attrs, attrs...)
	}
}

// WithDebug enables verbose span logging for this span when the tracer supports it.
func WithDebug(debug bool) SpanOption {
	return func(c *spanConfig) {
		c.debug = debug
	}
}

// StartConfig is the resolved configuration from [SpanOption]s.
type StartConfig struct {
	Kind  SpanKind
	Attrs []Attr
	Debug bool
}

// ApplySpanOptions resolves span options for backends.
func ApplySpanOptions(opts []SpanOption) StartConfig {
	return applySpanOptions(opts)
}

func applySpanOptions(opts []SpanOption) StartConfig {
	var cfg spanConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return StartConfig{
		Kind:  cfg.kind,
		Attrs: cfg.attrs,
		Debug: cfg.debug,
	}
}
