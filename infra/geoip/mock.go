package geoip

// MockResolver is an in-memory Resolver test double. It returns Result for any
// IP (with the IP field filled in), or Err when set.
type MockResolver struct {
	Result GeoInfo
	Err    error
}

// NewMockResolver returns a MockResolver that resolves every IP to result.
func NewMockResolver(result GeoInfo) *MockResolver {
	return &MockResolver{Result: result}
}

// Resolve implements Resolver.
func (m *MockResolver) Resolve(ip string) (GeoInfo, error) {
	if m.Err != nil {
		return GeoInfo{}, m.Err
	}
	out := m.Result
	out.IP = ip
	return out, nil
}

// Close implements Resolver.
func (m *MockResolver) Close() error { return nil }
