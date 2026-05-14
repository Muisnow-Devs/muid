package media

// Hard limits for user-supplied raster avatar staging objects and decode safety.
const (
	// MaxAvatarStagingBytes is the maximum object size (from HEAD Content-Length
	// and bytes read) accepted for a staging avatar upload.
	MaxAvatarStagingBytes = 15 << 20

	// MaxRasterDimension is the maximum width or height reported by image
	// metadata before full raster decode.
	MaxRasterDimension = 8192

	// MaxRasterPixelCount bounds width*height from metadata to mitigate
	// decompression / allocation bombs (decoded output is further cropped).
	MaxRasterPixelCount = 32_000_000
)
