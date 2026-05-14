package avatarkey

import "fmt"

// RootPrefix is the top-level R2 object key namespace for user avatars.
const RootPrefix = "avatars"

// UserObjectPrefix matches keys under avatars/<userID>/...
func UserObjectPrefix(userID string) string {
	return RootPrefix + "/" + userID + "/"
}

// StagingObjectKey is a pending upload key: avatars/<userID>/<leaf>.
func StagingObjectKey(userID, leaf string) string {
	return fmt.Sprintf("%s/%s/%s", RootPrefix, userID, leaf)
}

// ProductionWebPObjectKey is the final WebP asset key: avatars/<userID>/<rowID>.webp.
func ProductionWebPObjectKey(userID, rowID string) string {
	return fmt.Sprintf("%s/%s/%s.webp", RootPrefix, userID, rowID)
}
