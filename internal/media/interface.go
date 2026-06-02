package media

// RasterAvatarProcessor transforms user-uploaded raster images into square WebP avatars.
// Profile and any future service should depend on this interface; wire a concrete
// implementation from bootstrap.
type RasterAvatarProcessor interface {
	ProcessToSquareWebP(raw []byte, contentType string) ([]byte, error)
}
