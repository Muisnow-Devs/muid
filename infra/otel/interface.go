// Package oteltrace provides OpenTelemetry-backed implementations of [tracing.Tracer].
package oteltrace

import "sanzi.io/muid/pkg/shared/tracing"

// Tracer is the contract implemented by [NewTracer].
type Tracer = tracing.Tracer
