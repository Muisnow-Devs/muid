package templates

import (
	"errors"
	"strconv"
)

// ErrInvalidTemplatePath indicates locale or page identifiers that are unsafe
// for embedding in embedded template paths (e.g. path traversal).
var ErrInvalidTemplatePath = errors.New("templates: invalid template path")

// ErrMissingSubjectInLocaleBundle is returned when a locale JSON bundle has no usable "subject" entry.
var ErrMissingSubjectInLocaleBundle = errors.New("templates: missing subject string in locale bundle")

// ErrTemplateSubjectParseFailed wraps the text/template parse error for the subject line.
var ErrTemplateSubjectParseFailed = errors.New("templates: parse subject template failed")

// ErrTemplateSubjectExecFailed wraps execution errors for the subject text/template.
var ErrTemplateSubjectExecFailed = errors.New("templates: execute subject template failed")

// DetailError carries a short, non-sensitive explanation for expected validation failures.
type DetailError interface {
	error
	Detail() string
}

// InvalidTemplateSegmentError describes why a locale or page segment was rejected.
type InvalidTemplateSegmentError struct {
	Field  string
	Value  string
	Reason string // "empty", "dot_segment", "path_separator", "double_dot"
}

// Error implements [error].
func (e *InvalidTemplateSegmentError) Error() string {
	switch e.Reason {
	case "empty":
		return "templates: invalid " + e.Field + ": empty"
	case "dot_segment", "path_separator", "double_dot":
		return "templates: invalid " + e.Field + " " + strconv.Quote(e.Value)
	default:
		return "templates: invalid " + e.Field
	}
}

// Unwrap returns [ErrInvalidTemplatePath] for [errors.Is] / [errors.As] chains.
func (e *InvalidTemplateSegmentError) Unwrap() error { return ErrInvalidTemplatePath }

// Detail implements [DetailError].
func (e *InvalidTemplateSegmentError) Detail() string {
	switch e.Reason {
	case "empty":
		return e.Field + " is empty"
	case "dot_segment":
		return e.Field + " must not be '.' or '..'"
	case "path_separator":
		return e.Field + " must not contain path separators or NUL"
	case "double_dot":
		return e.Field + " must not contain '..'"
	default:
		return "invalid " + e.Field
	}
}
