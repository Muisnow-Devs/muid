// Command test-publish-otp publishes mail.send.otp for manual mailer testing.
//
// Example:
//
//	TEST_PUBLISH_OTP_NATS_URL=nats://127.0.0.1:4222 \
//	TEST_PUBLISH_OTP_EMAIL=you@example.com \
//	TEST_PUBLISH_OTP_LOCALE=en \
//	go run ./cmd/test/test-publish-otp
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

const configEnvPrefix = "TEST_PUBLISH_OTP"

type config struct {
	NATSURL        string `envconfig:"NATS_URL"`
	Email          string `envconfig:"EMAIL"`
	Locale         string `envconfig:"LOCALE"`
	Code           string `envconfig:"CODE"`
	ExpiresSeconds int    `envconfig:"EXPIRES_SECONDS" default:"300"`
}

func main() {
	publishinput.RegisterHelp(
		"Publish SendOTPEmailEvent to NATS (topic mail.send.otp).",
		configEnvPrefix,
		[]string{
			configEnvPrefix + "_NATS_URL        - NATS server (or MAILER_NATS_URL)",
			configEnvPrefix + "_EMAIL           - recipient (default: test@example.com)",
			configEnvPrefix + "_LOCALE          - template locale (default: en)",
			configEnvPrefix + "_CODE            - OTP code (default: 123456)",
			configEnvPrefix + "_EXPIRES_SECONDS - TTL seconds (default: 300, env only)",
		},
	)
	publishinput.ParseHelp()

	if err := run(); err != nil {
		log.Fatalf("publish otp event: %v", err)
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
	code, err := publishinput.Resolve(publishinput.Field{
		Name: "OTP code", EnvValue: cfg.Code, Default: "123456",
	})
	if err != nil {
		return err
	}

	expiresSec := cfg.ExpiresSeconds
	if expiresSec <= 0 {
		expiresSec = 300
	}

	ps, err := nats.NewNATSPubSub(natsURL)
	if err != nil {
		return fmt.Errorf("connect nats: %w", err)
	}
	defer errutil.CloseIf(ps)

	now := time.Now().UTC()
	expires := now.Add(time.Duration(expiresSec) * time.Second)

	ev := &mailpb.SendOTPEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(email)
	ev.SetLocale(locale)
	ev.SetCode(code)
	ev.SetExpiresAt(timestamppb.New(expires))
	ev.SetCreatedAt(timestamppb.New(now))

	payload, err := proto.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	err = ps.Publish(topics.TopicSendOTP, payload)
	if err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	log.Printf(
		"published topic=%s email=%s locale=%s bytes=%d",
		topics.TopicSendOTP, email, locale, len(payload),
	)
	return nil
}
