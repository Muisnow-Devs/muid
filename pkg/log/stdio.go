package log

import (
	"fmt"
	"os"
)

// Printf logs a formatted message at info level (startup / non-context paths).
func Printf(format string, args ...any) {
	Default().Info(fmt.Sprintf(format, args...))
}

// Println logs a message at info level.
func Println(args ...any) {
	Default().Info(fmt.Sprint(args...))
}

// Fatal logs at error level and exits with status 1.
func Fatal(args ...any) {
	Default().Error(fmt.Sprint(args...))
	os.Exit(1)
}

// Fatalf logs a formatted message at error level and exits with status 1.
func Fatalf(format string, args ...any) {
	Default().Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}
