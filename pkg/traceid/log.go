package traceid

import (
	"context"
	"log"
	"strings"
)

// LogUnexpected writes a single standard log line for non-client-facing failures.
// pairs must be even-length key/value strings (safe, non-secret fragments).
func LogUnexpected(ctx context.Context, reason, detail string, pairs ...string) {
	tid, ok := FromContext(ctx)
	if !ok || tid == "" {
		tid = "none"
	}
	var b strings.Builder
	if len(pairs) > 0 {
		if len(pairs)%2 != 0 {
			pairs = append(pairs, "kv", "odd")
		}
		for i := 0; i < len(pairs); i += 2 {
			b.WriteString(" ")
			b.WriteString(pairs[i])
			b.WriteString("=")
			b.WriteString(pairs[i+1])
		}
	}
	log.Printf("unexpected trace_id=%s reason=%s detail=%s%s", tid, reason, detail, b.String())
}
