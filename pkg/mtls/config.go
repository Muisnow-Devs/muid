package mtls

import (
	"errors"
	"strings"
)

var (
	ErrPartialPathGroup  = errors.New("mtls: certificate path group is partial")
	ErrRequiredPathGroup = errors.New("mtls: certificate path group is required")
)

// ValidatePathGroup requires paths to be either all blank or all nonblank. A
// required group may not be blank.
func ValidatePathGroup(required bool, paths ...string) error {
	configured := 0
	for _, path := range paths {
		if strings.TrimSpace(path) != "" {
			configured++
		}
	}
	if configured != 0 && configured != len(paths) {
		return ErrPartialPathGroup
	}
	if required && configured == 0 {
		return ErrRequiredPathGroup
	}
	return nil
}

// PathGroupConfigured reports whether a validated path group is configured.
func PathGroupConfigured(paths ...string) bool {
	if len(paths) == 0 {
		return false
	}
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			return false
		}
	}
	return true
}
