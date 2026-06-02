package media

// Hard limits for user-supplied raster avatar staging objects and decode safety.
const (
	// MaxAvatarStagingBytes is the maximum object size accepted for a staging avatar upload.
	MaxAvatarStagingBytes = 15 << 20

	// MaxRasterDimension is the maximum width or height accepted before full raster decode.
	MaxRasterDimension = 8192

	// MaxRasterPixelCount bounds width*height from metadata to mitigate decompression bombs.
	MaxRasterPixelCount = 32_000_000
)
