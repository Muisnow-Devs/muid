package app

import "testing"

func TestConfigValidateTLSGroups(t *testing.T) {
	t.Parallel()

	validDebug := Config{
		Debug:                 true,
		Port:                  5315,
		InternalPort:          5316,
		DatabaseURL:           "postgres://authz",
		NATSURL:               "nats://localhost:4222",
		PolicyReloadSeconds:   300,
		RequestTimeoutSeconds: 10,
		GRPCTLSCertPath:       "server.pem",
		GRPCTLSKeyPath:        "server-key.pem",
		GRPCMTLSClientCAPath:  "clients.pem",
		GRPCClientCertPath:    "client.pem",
		GRPCClientKeyPath:     "client-key.pem",
		GRPCRootCAPath:        "servers.pem",
	}
	validProduction := validDebug
	validProduction.Debug = false

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{name: "debug mutual TLS", config: validDebug},
		{name: "debug plaintext", config: func() Config {
			config := validDebug
			config.GRPCTLSCertPath = ""
			config.GRPCTLSKeyPath = ""
			config.GRPCMTLSClientCAPath = ""
			config.GRPCClientCertPath = ""
			config.GRPCClientKeyPath = ""
			config.GRPCRootCAPath = ""
			return config
		}(), wantErr: true},
		{name: "production mutual TLS", config: validProduction},
		{name: "production missing groups", config: func() Config {
			config := Config{
				Port:                  5315,
				InternalPort:          5316,
				DatabaseURL:           "postgres://authz",
				NATSURL:               "nats://localhost:4222",
				PolicyReloadSeconds:   300,
				RequestTimeoutSeconds: 10,
			}
			config.Debug = false
			return config
		}(), wantErr: true},
		{name: "partial server group", config: func() Config {
			config := validDebug
			config.GRPCTLSKeyPath = ""
			return config
		}(), wantErr: true},
		{name: "partial client group", config: func() Config {
			config := validDebug
			config.GRPCRootCAPath = ""
			return config
		}(), wantErr: true},
		{name: "same listeners", config: func() Config {
			config := validDebug
			config.InternalPort = config.Port
			return config
		}(), wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			if (err != nil) != test.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
