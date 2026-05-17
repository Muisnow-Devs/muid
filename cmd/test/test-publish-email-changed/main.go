// Command test-publish-email-changed publishes mail.send.email_changed for manual mailer testing.
//
// Example:
//
//	TEST_PUBLISH_EMAIL_CHANGED_NATS_URL=nats://127.0.0.1:4222 \
//	TEST_PUBLISH_EMAIL_CHANGED_EMAIL=you@example.com \
//	TEST_PUBLISH_EMAIL_CHANGED_LOCALE=en \
//	go run ./cmd/test/test-publish-email-changed
package main

import (
	"fmt"
	"log"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/cmd/test/publishinput"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/topics"
)

const configEnvPrefix = "TEST_PUBLISH_EMAIL_CHANGED"

type config struct {
	NATSURL  string `envconfig:"NATS_URL"`
	Email    string `envconfig:"EMAIL"`
	Locale   string `envconfig:"LOCALE"`
	OldEmail string `envconfig:"OLD_EMAIL"`
	NewEmail string `envconfig:"NEW_EMAIL"`
}

func main() {
	publishinput.RegisterHelp(
		"Publish SendEmailChangedEvent to NATS (topic mail.send.email_changed).",
		configEnvPrefix,
		[]string{
			configEnvPrefix + "_NATS_URL   - NATS server (or MAILER_NATS_URL)",
			configEnvPrefix + "_EMAIL      - recipient (default: test@example.com)",
			configEnvPrefix + "_LOCALE     - template locale (default: en)",
			configEnvPrefix + "_OLD_EMAIL  - previous address (default: old@example.com)",
			configEnvPrefix + "_NEW_EMAIL  - new address (default: same as EMAIL)",
		},
	)
	publishinput.ParseHelp()

	if err := run(); err != nil {
		log.Fatalf("publish email changed event: %v", err)
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
	oldEmail, err := publishinput.Resolve(publishinput.Field{
		Name: "Old email", EnvValue: cfg.OldEmail, Default: "old@example.com",
	})
	if err != nil {
		return err
	}
	newEmail, err := publishinput.Resolve(publishinput.Field{
		Name: "New email", EnvValue: cfg.NewEmail, Default: email,
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
	ev := &mailpb.SendEmailChangedEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(email)
	ev.SetLocale(locale)
	ev.SetOldEmail(oldEmail)
	ev.SetNewEmail(newEmail)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	payload, err := proto.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if err := ps.Publish(topics.TopicEmailChanged, payload); err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	log.Printf(
		"published topic=%s email=%s locale=%s old=%s new=%s bytes=%d",
		topics.TopicEmailChanged, email, locale, oldEmail, newEmail, len(payload),
	)
	return nil
}
