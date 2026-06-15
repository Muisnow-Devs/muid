package httpmeta_test

import (
	"context"
	"net/http"
	"testing"

	"google.golang.org/grpc/metadata"

	"sanzi.io/muid/pkg/gateway/httpmeta"
)

func TestClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		remote       string
		headers      map[string]string
		trust        bool
		realIPHeader string
		want         string
	}{
		{
			name:   "remote addr fallback",
			remote: "203.0.113.7:54321",
			want:   "203.0.113.7",
		},
		{
			name:    "xff ignored when untrusted",
			remote:  "10.0.0.1:1000",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4"},
			trust:   false,
			want:    "10.0.0.1",
		},
		{
			name:    "xff uses right-most hop when trusted",
			remote:  "10.0.0.1:1000",
			headers: map[string]string{"X-Forwarded-For": "1.2.3.4, 70.0.0.9"},
			trust:   true,
			want:    "70.0.0.9",
		},
		{
			name:         "real ip header preferred over xff when trusted",
			remote:       "10.0.0.1:1000",
			headers:      map[string]string{"CF-Connecting-IP": "9.9.9.9", "X-Forwarded-For": "1.2.3.4, 70.0.0.9"},
			trust:        true,
			realIPHeader: "CF-Connecting-IP",
			want:         "9.9.9.9",
		},
		{
			name:    "real ip when trusted and no xff",
			remote:  "10.0.0.1:1000",
			headers: map[string]string{"X-Real-IP": "5.6.7.8"},
			trust:   true,
			want:    "5.6.7.8",
		},
		{
			name:         "real ip header ignored when untrusted",
			remote:       "10.0.0.1:1000",
			headers:      map[string]string{"CF-Connecting-IP": "9.9.9.9"},
			trust:        false,
			realIPHeader: "CF-Connecting-IP",
			want:         "10.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := &http.Request{RemoteAddr: tc.remote, Header: http.Header{}}
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			got := httpmeta.ClientIP(r, httpmeta.ClientIPConfig{
				TrustForwardHeader: tc.trust,
				RealIPHeader:       tc.realIPHeader,
			})
			if got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWithOutgoing(t *testing.T) {
	t.Parallel()

	ctx := httpmeta.WithOutgoing(context.Background(), httpmeta.Fields{
		UserID:     "11111111-1111-1111-1111-111111111111",
		ClientIP:   "1.2.3.4",
		GeoCountry: "US",
	})
	md, ok := metadata.FromOutgoingContext(ctx)
	if !ok {
		t.Fatal("expected outgoing metadata")
	}
	if got := md.Get(httpmeta.UserIDKey); len(got) != 1 || got[0] != "11111111-1111-1111-1111-111111111111" {
		t.Fatalf("user id metadata = %v", got)
	}
	if got := md.Get(httpmeta.ClientIPKey); len(got) != 1 || got[0] != "1.2.3.4" {
		t.Fatalf("client ip metadata = %v", got)
	}
	if got := md.Get(httpmeta.GeoCountryKey); len(got) != 1 || got[0] != "US" {
		t.Fatalf("geo metadata = %v", got)
	}
}

func TestWithOutgoingSkipsEmpty(t *testing.T) {
	t.Parallel()

	ctx := httpmeta.WithOutgoing(context.Background(), httpmeta.Fields{})
	if _, ok := metadata.FromOutgoingContext(ctx); ok {
		t.Fatal("expected no outgoing metadata for empty fields")
	}
}
