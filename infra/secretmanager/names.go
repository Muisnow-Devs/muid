package secretmanager

import (
	"fmt"
	"strings"

	gsm "sanzi.io/muid/pkg/shared/secretmanager"
)

const (
	secretNamePrefix = "projects/"
	versionsSegment  = "/versions/"
)

func resolveSecretName(projectID, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", gsm.ErrInvalidSecretRef
	}
	if strings.HasPrefix(name, secretNamePrefix) {
		if !strings.Contains(name, "/secrets/") {
			return "", gsm.ErrInvalidSecretRef
		}
		return name, nil
	}
	projectID = strings.TrimSpace(projectID)
	if projectID == "" {
		return "", gsm.ErrEmptyProjectID
	}
	if strings.Contains(name, "/") {
		return "", gsm.ErrInvalidSecretRef
	}
	return fmt.Sprintf("projects/%s/secrets/%s", projectID, name), nil
}

func resolveVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || version == "latest" {
		return "latest"
	}
	return version
}

func versionResourceName(secretName, version string) (string, error) {
	version = resolveVersion(version)
	if version == "latest" {
		return secretName + versionsSegment + "latest", nil
	}
	if strings.Contains(version, "/") {
		return "", gsm.ErrInvalidSecretRef
	}
	return secretName + versionsSegment + version, nil
}

func explicitVersionResourceName(secretName, version string) (string, error) {
	version = strings.TrimSpace(version)
	if version == "" || version == "latest" {
		return "", gsm.ErrInvalidSecretRef
	}
	if strings.Contains(version, "/") {
		return "", gsm.ErrInvalidSecretRef
	}
	return secretName + versionsSegment + version, nil
}

func versionIDFromResourceName(resource string) string {
	idx := strings.LastIndex(resource, versionsSegment)
	if idx < 0 {
		return ""
	}
	return resource[idx+len(versionsSegment):]
}
