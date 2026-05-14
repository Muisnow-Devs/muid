package media

// RasterAvatarProcessor normalizes user-uploaded raster images for avatar use:
// decode, center-crop to square, downscale to a fixed max edge, encode as WebP.
// Profile (and any future service) should depend on this interface; wire a concrete
// implementation from bootstrap.
type RasterAvatarProcessor interface {
	ProcessToSquareWebP(raw []byte, contentType string) ([]byte, error)
}
