package publishinput

import (
	"strings"
	"testing"

	"sanzi.io/muid/pkg/shared/pubsub"
)

func TestResolve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		field   Field
		want    string
		wantErr bool
	}{
		{
			name: "env set ignores stdin",
			field: Field{
				Name:     "Email",
				EnvValue: "from-env@example.com",
				Default:  "default@example.com",
				Stdin:    strings.NewReader("from-stdin@example.com\n"),
			},
			want: "from-env@example.com",
		},
		{
			name: "stdin used when env empty",
			field: Field{
				Name:     "Email",
				EnvValue: "",
				Default:  "default@example.com",
				Stdin:    strings.NewReader("typed@example.com\n"),
			},
			want: "typed@example.com",
		},
		{
			name: "blank stdin line uses default",
			field: Field{
				Name:     "Locale",
				EnvValue: "",
				Default:  "en",
				Stdin:    strings.NewReader("\n"),
			},
			want: "en",
		},
		{
			name: "eof with default",
			field: Field{
				Name:     "Locale",
				EnvValue: "",
				Default:  "en",
				Stdin:    strings.NewReader(""),
			},
			want: "en",
		},
		{
			name: "required when no env stdin or default",
			field: Field{
				Name:     "Email",
				EnvValue: "",
				Default:  "",
				Stdin:    strings.NewReader("\n"),
			},
			wantErr: true,
		},
		{
			name: "env whitespace trimmed",
			field: Field{
				Name:     "Email",
				EnvValue: "  a@b.c  ",
				Stdin:    strings.NewReader("ignored\n"),
			},
			want: "a@b.c",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Resolve(tt.field)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveNATSURL(t *testing.T) {
	const mailerURL = "nats://mailer:4222"
	const configURL = "nats://from-config:4222"
	const stdinURL = "nats://from-stdin:4222"

	tests := []struct {
		name       string
		fromConfig string
		mailerEnv  string
		stdin      string
		want       string
	}{
		{
			name:       "config wins",
			fromConfig: configURL,
			mailerEnv:  mailerURL,
			stdin:      stdinURL + "\n",
			want:       configURL,
		},
		{
			name:       "mailer env when config empty",
			fromConfig: "",
			mailerEnv:  mailerURL,
			stdin:      stdinURL + "\n",
			want:       mailerURL,
		},
		{
			name:       "stdin when config and mailer empty",
			fromConfig: "",
			mailerEnv:  "",
			stdin:      stdinURL + "\n",
			want:       stdinURL,
		},
		{
			name:       "default when all empty",
			fromConfig: "",
			mailerEnv:  "",
			stdin:      "\n",
			want:       "nats://127.0.0.1:4222",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("MAILER_NATS_URL", tt.mailerEnv)

			got, err := ResolveNATSURL(tt.fromConfig, strings.NewReader(tt.stdin))
			if err != nil {
				t.Fatalf("ResolveNATSURL: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReliableMailPublishOptions(t *testing.T) {
	t.Parallel()

	got := ReliableMailPublishOptions()
	if !got.Reliable {
		t.Fatal("Reliable = false, want true")
	}
	if got.RetryPolicy != pubsub.CriticalRetryPolicy() {
		t.Fatalf("RetryPolicy = %#v, want %#v", got.RetryPolicy, pubsub.CriticalRetryPolicy())
	}
}
