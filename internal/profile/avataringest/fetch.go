package avataringest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"sanzi.io/muid/internal/media"
)

var errAvatarFetchHostBlocked = errors.New("avatar fetch: host or IP not allowed")

// avatarFetchHostLookup is swapped in tests to mock DNS resolution.
var avatarFetchHostLookup = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func avatarFetchIPBlocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() ||
		!ip.IsGlobalUnicast()
}

func validateAvatarFetchResolvedIPs(ips []net.IP) error {
	if len(ips) == 0 {
		return errAvatarFetchHostBlocked
	}
	for _, ip := range ips {
		if avatarFetchIPBlocked(ip) {
			return errAvatarFetchHostBlocked
		}
	}
	return nil
}

func validateAvatarFetchHost(host string) error {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "" {
		return errAvatarFetchHostBlocked
	}
	if ip := net.ParseIP(h); ip != nil {
		if avatarFetchIPBlocked(ip) {
			return errAvatarFetchHostBlocked
		}
		return nil
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return errAvatarFetchHostBlocked
	}
	if strings.HasPrefix(h, "127.") {
		return errAvatarFetchHostBlocked
	}
	switch h {
	case "metadata.google.internal", "metadata", "169.254.169.254":
		return errAvatarFetchHostBlocked
	default:
		return nil
	}
}

// ensureAvatarFetchHostResolved performs DNS resolution and rejects hosts that map to
// non-public addresses (SSRF protection). Literal IPs are validated by validateAvatarFetchHost only.
func ensureAvatarFetchHostResolved(ctx context.Context, host string) error {
	h := strings.TrimSpace(host)
	if h == "" {
		return errAvatarFetchHostBlocked
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	ips, err := avatarFetchHostLookup(ctx, h)
	if err != nil {
		return fmt.Errorf("avatar fetch: resolve host: %w", err)
	}
	return validateAvatarFetchResolvedIPs(ips)
}

// fetchHTTPSAvatarSource downloads an avatar raster source over HTTPS with a byte cap.
// Response body length must match Content-Length when that header is present and valid.
func fetchHTTPSAvatarSource(ctx context.Context, rawURL string) ([]byte, string, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, "", fmt.Errorf("avatar fetch: require https URL with host")
	}
	if err := validateAvatarFetchHost(parsed.Hostname()); err != nil {
		return nil, "", err
	}
	if err := ensureAvatarFetchHostResolved(ctx, parsed.Hostname()); err != nil {
		return nil, "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "muid-profile-avataringest/1.0")

	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("avatar fetch: unexpected HTTP status %d", resp.StatusCode)
	}

	cl := resp.ContentLength
	if cl > media.MaxAvatarStagingBytes {
		return nil, "", media.ErrRasterObjectTooLarge
	}

	maxRead := int64(media.MaxAvatarStagingBytes + 1)
	if cl >= 0 && cl <= media.MaxAvatarStagingBytes {
		maxRead = cl + 1
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRead))
	if err != nil {
		return nil, "", err
	}
	if int64(len(body)) > media.MaxAvatarStagingBytes {
		return nil, "", media.ErrRasterObjectTooLarge
	}
	if cl >= 0 && int64(len(body)) != cl {
		return nil, "", fmt.Errorf("avatar fetch: body length does not match Content-Length")
	}

	ct := resp.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return body, ct, nil
}
