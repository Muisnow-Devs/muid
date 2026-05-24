// Package publishinput resolves mail test publisher fields from env or stdin.
package publishinput

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"sanzi.io/muid/pkg/shared/pubsub"
)

// Field resolves a single value: a non-empty EnvValue wins; otherwise one line is read from stdin.
type Field struct {
	Name     string
	EnvValue string
	Default  string
	Stdin    io.Reader
}

// Resolve returns the field value using env-first, then stdin, then Default.
func Resolve(f Field) (string, error) {
	if v := strings.TrimSpace(f.EnvValue); v != "" {
		return v, nil
	}

	in := f.Stdin
	if in == nil {
		in = os.Stdin
	}

	prompt := f.Name
	if f.Default != "" {
		prompt = fmt.Sprintf("%s [%s]", f.Name, f.Default)
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)

	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	v := strings.TrimSpace(line)
	if v == "" {
		v = f.Default
	}
	if v == "" {
		return "", fmt.Errorf("%s is required", f.Name)
	}
	return v, nil
}

// ResolveNATSURL returns NATS URL from envconfig value, else MAILER_NATS_URL, else stdin.
// Pass non-nil stdin in tests; production callers may pass nil to use os.Stdin.
func ResolveNATSURL(fromConfig string, stdin io.Reader) (string, error) {
	if v := strings.TrimSpace(fromConfig); v != "" {
		return v, nil
	}
	if v := strings.TrimSpace(os.Getenv("MAILER_NATS_URL")); v != "" {
		return v, nil
	}
	return Resolve(Field{
		Name:    "NATS URL",
		Default: "nats://127.0.0.1:4222",
		Stdin:   stdin,
	})
}

// ReliableMailPublishOptions matches mailer durable subscriptions for manual test publishers.
func ReliableMailPublishOptions() pubsub.PublishOptions {
	return pubsub.PublishOptions{
		Reliable:    true,
		RetryPolicy: pubsub.CriticalRetryPolicy(),
	}
}

// RegisterHelp installs -h / -help and a usage block listing env vars.
func RegisterHelp(title, envPrefix string, envLines []string) {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n\n", title)
		fmt.Fprintf(
			os.Stderr,
			"Environment variables (%s_*); when set, stdin is ignored for that field:\n",
			envPrefix,
		)
		for _, line := range envLines {
			fmt.Fprintf(os.Stderr, "  %s\n", line)
		}
		fmt.Fprintf(
			os.Stderr,
			"\nFallback: MAILER_NATS_URL when %s_NATS_URL is unset.\n",
			envPrefix,
		)
		fmt.Fprintf(
			os.Stderr,
			"Unset EMAIL/LOCALE (and other optional fields) prompt on stdin.\n\n",
		)
		fmt.Fprintln(os.Stderr, "Flags:")
		flag.PrintDefaults()
	}
}

// ParseHelp exits after printing usage when -h is set (-help uses flag.Usage via RegisterHelp).
func ParseHelp() {
	showHelp := flag.Bool("h", false, "show help")
	flag.Parse()
	if *showHelp {
		flag.Usage()
		os.Exit(0)
	}
}
