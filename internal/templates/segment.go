package templates

import (
	"errors"
	"fmt"
	"strings"
)

// ErrInvalidTemplatePath indicates locale or page identifiers that are unsafe
// for embedding in embedded template paths (e.g. path traversal).
var ErrInvalidTemplatePath = errors.New("templates: invalid template path")

func validateTemplateSegment(s, field string) error {
	if s == "" {
		return fmt.Errorf("templates: invalid %s: empty: %w", field, ErrInvalidTemplatePath)
	}

	if s == "." || s == ".." {
		return fmt.Errorf("templates: invalid %s %q: %w", field, s, ErrInvalidTemplatePath)
	}

	if strings.ContainsAny(s, "/\\\x00") {
		return fmt.Errorf("templates: invalid %s %q: %w", field, s, ErrInvalidTemplatePath)
	}

	if strings.Contains(s, "..") {
		return fmt.Errorf("templates: invalid %s %q: %w", field, s, ErrInvalidTemplatePath)
	}

	return nil
}
