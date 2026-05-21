package utils

import "strings"

func DefaultIfEmpty(value *string, fallback string) {
	if strings.TrimSpace(*value) == "" {
		*value = fallback
	}
}

func DefaultIfFalse(value *bool, fallback bool) {
	if !*value {
		*value = fallback
	}
}
