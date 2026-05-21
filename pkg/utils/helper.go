package utils

import "strings"

func DefaultIfEmpty(value *string, fallback string) {
	if strings.TrimSpace(*value) == "" {
		*value = fallback
	}
}

func DefaultIfEmptyFunc(value *string, fallbackFunc func() string) {
	if strings.TrimSpace(*value) == "" {
		*value = fallbackFunc()
	}
}

func FuncIfExists(value *string, funcIfExists func(string)) {
	if strings.TrimSpace(*value) != "" {
		funcIfExists(*value)
	}
}

func DefaultIfFalse(value *bool, fallback bool) {
	if !*value {
		*value = fallback
	}
}
