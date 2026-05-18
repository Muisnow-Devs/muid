package avataringest

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestValidateAvatarFetchHost(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		host string
		ok   bool
	}{
		{"github.com", true},
		{"avatars.githubusercontent.com", true},
		{"localhost", false},
		{"app.localhost", false},
		{"127.0.0.1", false},
		{"127.0.0.2", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"192.168.0.1", false},
		{"0.0.0.0", false},
		{"::1", false},
		{"::", false},
		{"fe80::1", false},
		{"fc00::1", false},
		{"224.0.0.1", false},
		{"8.8.8.8", true},
		{"93.184.216.34", true},
		{"2606:2800:220:1:248:1893:25c8:1946", true},
		{"metadata.google.internal", false},
		{"169.254.169.254", false},
	} {
		tc := tc
		t.Run(tc.host, func(t *testing.T) {
			t.Parallel()
			err := validateAvatarFetchHost(tc.host)
			if tc.ok && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected blocked")
			}
		})
	}
}

func TestValidateAvatarFetchResolvedIPs(t *testing.T) {
	t.Parallel()
	public := net.ParseIP("93.184.216.34")
	for _, tc := range []struct {
		name string
		ips  []net.IP
		ok   bool
	}{
		{"empty", nil, false},
		{"public_v4", []net.IP{public}, true},
		{"public_v6", []net.IP{net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")}, true},
		{"loopback_v4", []net.IP{net.ParseIP("127.0.0.1")}, false},
		{"loopback_v6", []net.IP{net.ParseIP("::1")}, false},
		{"rfc1918_10", []net.IP{net.ParseIP("10.1.2.3")}, false},
		{"rfc1918_192", []net.IP{net.ParseIP("192.168.1.1")}, false},
		{"link_local_metadata", []net.IP{net.ParseIP("169.254.169.254")}, false},
		{"unspecified", []net.IP{net.ParseIP("0.0.0.0")}, false},
		{"mixed_public_then_private", []net.IP{public, net.ParseIP("10.0.0.1")}, false},
		{"mixed_private_then_public", []net.IP{net.ParseIP("10.0.0.1"), public}, false},
		{"multiple_public", []net.IP{public, net.ParseIP("8.8.8.8")}, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateAvatarFetchResolvedIPs(tc.ips)
			if tc.ok && err != nil {
				t.Fatalf("expected ok, got %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("expected blocked")
			}
		})
	}
}

func TestEnsureAvatarFetchHostResolved(t *testing.T) {
	t.Parallel()

	orig := avatarFetchHostLookup
	t.Cleanup(func() { avatarFetchHostLookup = orig })

	public := net.ParseIP("93.184.216.34")
	lookupOK := func(ips []net.IP) func(context.Context, string) ([]net.IP, error) {
		return func(context.Context, string) ([]net.IP, error) {
			return ips, nil
		}
	}
	lookupErr := func(err error) func(context.Context, string) ([]net.IP, error) {
		return func(context.Context, string) ([]net.IP, error) {
			return nil, err
		}
	}

	for _, tc := range []struct {
		name    string
		host    string
		lookup  func(context.Context, string) ([]net.IP, error)
		wantErr error
	}{
		{
			name: "literal_public_ip_skips_lookup",
			host: "8.8.8.8",
			lookup: func(context.Context, string) ([]net.IP, error) {
				t.Fatal("lookup should not run for literal IP")
				return nil, nil
			},
		},
		{
			name:   "hostname_public",
			host:   "example.com",
			lookup: lookupOK([]net.IP{public}),
		},
		{
			name:    "hostname_private",
			host:    "internal.example",
			lookup:  lookupOK([]net.IP{net.ParseIP("10.0.0.1")}),
			wantErr: errAvatarFetchHostBlocked,
		},
		{
			name:    "hostname_loopback",
			host:    "loopback.example",
			lookup:  lookupOK([]net.IP{net.ParseIP("127.0.0.1")}),
			wantErr: errAvatarFetchHostBlocked,
		},
		{
			name:    "hostname_metadata_ip",
			host:    "metadata.example",
			lookup:  lookupOK([]net.IP{net.ParseIP("169.254.169.254")}),
			wantErr: errAvatarFetchHostBlocked,
		},
		{
			name:    "hostname_ipv6_loopback",
			host:    "v6loop.example",
			lookup:  lookupOK([]net.IP{net.ParseIP("::1")}),
			wantErr: errAvatarFetchHostBlocked,
		},
		{
			name:    "hostname_any_private_record",
			host:    "mixed.example",
			lookup:  lookupOK([]net.IP{public, net.ParseIP("192.168.1.1")}),
			wantErr: errAvatarFetchHostBlocked,
		},
		{
			name:    "hostname_no_records",
			host:    "empty.example",
			lookup:  lookupOK(nil),
			wantErr: errAvatarFetchHostBlocked,
		},
		{
			name:    "lookup_failure",
			host:    "missing.example",
			lookup:  lookupErr(errors.New("no such host")),
			wantErr: errors.New("no such host"),
		},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			avatarFetchHostLookup = tc.lookup
			err := ensureAvatarFetchHostResolved(context.Background(), tc.host)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("expected ok, got %v", err)
			case tc.wantErr != nil && err == nil:
				t.Fatalf("expected error %v, got nil", tc.wantErr)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				if tc.wantErr.Error() != "" && err != nil &&
					err.Error() == "avatar fetch: resolve host: "+tc.wantErr.Error() {
					return
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
			}
		})
	}
}
