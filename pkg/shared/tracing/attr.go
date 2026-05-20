package tracing

// StringAttr returns a string-valued attribute.
func StringAttr(key, value string) Attr {
	return Attr{Key: key, Value: value}
}

// Int64Attr returns an int64-valued attribute.
func Int64Attr(key string, value int64) Attr {
	return Attr{Key: key, Value: value}
}

// BoolAttr returns a bool-valued attribute.
func BoolAttr(key string, value bool) Attr {
	return Attr{Key: key, Value: value}
}
