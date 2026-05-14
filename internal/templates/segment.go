package templates

import "strings"

func validateTemplateSegment(s, field string) error {
	if s == "" {
		return &InvalidTemplateSegmentError{Field: field, Value: s, Reason: "empty"}
	}

	if s == "." || s == ".." {
		return &InvalidTemplateSegmentError{Field: field, Value: s, Reason: "dot_segment"}
	}

	if strings.ContainsAny(s, "/\\\x00") {
		return &InvalidTemplateSegmentError{Field: field, Value: s, Reason: "path_separator"}
	}

	if strings.Contains(s, "..") {
		return &InvalidTemplateSegmentError{Field: field, Value: s, Reason: "double_dot"}
	}

	return nil
}
