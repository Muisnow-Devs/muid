package r2

import "strings"

// PublicObjectURL joins a CDN or public origin base URL with an object key.
func PublicObjectURL(baseURL, objectKey string) string {
	base := strings.TrimRight(baseURL, "/")
	return base + "/" + strings.TrimLeft(objectKey, "/")
}
