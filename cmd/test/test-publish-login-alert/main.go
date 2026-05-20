// Command test-publish-login-alert publishes mail.send.login_alert for manual mailer testing.
//
// Example:
//
//	TEST_PUBLISH_LOGIN_ALERT_NATS_URL=nats://127.0.0.1:4222 \
//	TEST_PUBLISH_LOGIN_ALERT_EMAIL=you@example.com \
//	TEST_PUBLISH_LOGIN_ALERT_LOCALE=en \
//	go run ./cmd/test/test-publish-login-alert
package main

import (
	"fmt"
	"time"

	"sanzi.io/muid/pkg/log"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/cmd/test/publishinput"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/topics"
)

const configEnvPrefix = "TEST_PUBLISH_LOGIN_ALERT"

type config struct {
	NATSURL    string `envconfig:"NATS_URL"`
	Email      string `envconfig:"EMAIL"`
	Locale     string `envconfig:"LOCALE"`
	IPAddress  string `envconfig:"IP_ADDRESS"`
	Location   string `envconfig:"LOCATION"`
	Device     string `envconfig:"DEVICE"`
	UserAgent  string `envconfig:"USER_AGENT"`
	SecureLink string `envconfig:"SECURE_LINK"`
}

func main() {
	publishinput.RegisterHelp(
		"Publish SendLoginAlertEmailEvent to NATS (topic mail.send.login_alert).",
		configEnvPrefix,
		[]string{
			configEnvPrefix + "_NATS_URL     - NATS server (or MAILER_NATS_URL)",
			configEnvPrefix + "_EMAIL        - recipient (default: test@example.com)",
			configEnvPrefix + "_LOCALE       - template locale (default: en)",
			configEnvPrefix + "_IP_ADDRESS   - default: 203.0.113.1",
			configEnvPrefix + "_LOCATION     - default: Taipei, TW",
			configEnvPrefix + "_DEVICE       - default: Chrome on Windows",
			configEnvPrefix + "_USER_AGENT   - default: Mozilla/5.0 (test-publish-login-alert)",
			configEnvPrefix + "_SECURE_LINK  - default: https://example.com/account/security",
		},
	)
	publishinput.ParseHelp()

	if err := run(); err != nil {
		log.Fatalf("publish login alert event: %v", err)
	}
}

func run() error {
	cfg, err := shared.LoadConfig[config](configEnvPrefix)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	natsURL, err := publishinput.ResolveNATSURL(cfg.NATSURL, nil)
	if err != nil {
		return err
	}

	email, err := publishinput.Resolve(publishinput.Field{
		Name: "Recipient email", EnvValue: cfg.Email, Default: "test@example.com",
	})
	if err != nil {
		return err
	}
	locale, err := publishinput.Resolve(publishinput.Field{
		Name: "Locale", EnvValue: cfg.Locale, Default: "en",
	})
	if err != nil {
		return err
	}
	ipAddress, err := publishinput.Resolve(publishinput.Field{
		Name: "IP address", EnvValue: cfg.IPAddress, Default: "203.0.113.1",
	})
	if err != nil {
		return err
	}
	location, err := publishinput.Resolve(publishinput.Field{
		Name: "Location", EnvValue: cfg.Location, Default: "Taipei, TW",
	})
	if err != nil {
		return err
	}
	device, err := publishinput.Resolve(publishinput.Field{
		Name: "Device", EnvValue: cfg.Device, Default: "Chrome on Windows",
	})
	if err != nil {
		return err
	}
	userAgent, err := publishinput.Resolve(publishinput.Field{
		Name: "User agent", EnvValue: cfg.UserAgent, Default: "Mozilla/5.0 (test-publish-login-alert)",
	})
	if err != nil {
		return err
	}
	secureLink, err := publishinput.Resolve(publishinput.Field{
		Name: "Secure link", EnvValue: cfg.SecureLink, Default: "https://example.com/account/security",
	})
	if err != nil {
		return err
	}

	ps, err := nats.NewNATSPubSub(natsURL)
	if err != nil {
		return fmt.Errorf("connect nats: %w", err)
	}
	defer errutil.CloseIf(ps)

	now := time.Now().UTC()

	ev := &mailpb.SendLoginAlertEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(email)
	ev.SetLocale(locale)
	ev.SetIpAddress(ipAddress)
	ev.SetLocation(location)
	ev.SetDevice(device)
	ev.SetUserAgent(userAgent)
	ev.SetSecureLink(secureLink)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	payload, err := proto.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	err = ps.Publish(topics.TopicSendLoginAlert, payload)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	log.Printf(
		"published topic=%s email=%s locale=%s bytes=%d",
		topics.TopicSendLoginAlert, email, locale, len(payload),
	)
	return nil
}
