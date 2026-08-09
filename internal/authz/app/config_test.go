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
	}
	validProduction := validDebug
	validProduction.Debug = false
	validProduction.GRPCTLSCertPath = "server.pem"
	validProduction.GRPCTLSKeyPath = "server-key.pem"
	validProduction.GRPCMTLSClientCAPath = "clients.pem"
	validProduction.GRPCClientCertPath = "client.pem"
	validProduction.GRPCClientKeyPath = "client-key.pem"
	validProduction.GRPCRootCAPath = "servers.pem"

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{name: "debug plaintext", config: validDebug},
		{name: "production mutual TLS", config: validProduction},
		{name: "production missing groups", config: func() Config {
			config := validDebug
			config.Debug = false
			return config
		}(), wantErr: true},
		{name: "partial server group", config: func() Config {
			config := validDebug
			config.GRPCTLSCertPath = "server.pem"
			return config
		}(), wantErr: true},
		{name: "partial client group", config: func() Config {
			config := validDebug
			config.GRPCClientCertPath = "client.pem"
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
