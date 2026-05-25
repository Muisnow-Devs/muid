package handlers

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"sanzi.io/muid/pkg/localetime"
)

// FormatEventTime formats a protobuf timestamp for mail templates using locale and timezone.
func FormatEventTime(ts *timestamppb.Timestamp, timezone string) string {
	instant := time.Now().UTC()
	if ts != nil {
		instant = ts.AsTime()
	}

	return localetime.Format(instant, timezone)
}
