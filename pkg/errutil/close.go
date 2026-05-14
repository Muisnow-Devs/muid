package errutil

import "io"

// Close calls c.Close and discards the error (for defer paths or cleanup after a failed setup).
func Close(c io.Closer) {
	if c == nil {
		return
	}
	Discard(c.Close())
}

// CloseIf calls Close when v implements io.Closer.
func CloseIf(v any) {
	if c, ok := v.(io.Closer); ok {
		Close(c)
	}
}
