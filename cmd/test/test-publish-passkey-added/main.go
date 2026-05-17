// Command test-publish-passkey-added publishes mail.send.passkey_added for manual mailer testing.
//
// Example:
//
//	TEST_PUBLISH_PASSKEY_ADDED_NATS_URL=nats://127.0.0.1:4222 \
//	TEST_PUBLISH_PASSKEY_ADDED_EMAIL=you@example.com \
//	TEST_PUBLISH_PASSKEY_ADDED_LOCALE=zh-TW \
//	go run ./cmd/test/test-publish-passkey-added
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

const configEnvPrefix = "TEST_PUBLISH_PASSKEY_ADDED"

type config struct {
	NATSURL     string `envconfig:"NATS_URL"`
	Email       string `envconfig:"EMAIL"`
	Locale      string `envconfig:"LOCALE"`
	PasskeyName string `envconfig:"PASSKEY_NAME"`
}

func main() {
	publishinput.RegisterHelp(
		"Publish SendPasskeyAddedEmailEvent to NATS (topic mail.send.passkey_added).",
		configEnvPrefix,
		[]string{
			configEnvPrefix + "_NATS_URL      - NATS server (or MAILER_NATS_URL)",
			configEnvPrefix + "_EMAIL         - recipient (default: test@example.com)",
			configEnvPrefix + "_LOCALE        - template locale (default: en)",
			configEnvPrefix + "_PASSKEY_NAME  - display name in email (default: Passkey)",
		},
	)
	publishinput.ParseHelp()

	if err := run(); err != nil {
		log.Fatalf("publish passkey added event: %v", err)
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
	passkeyName, err := publishinput.Resolve(publishinput.Field{
		Name: "Passkey name", EnvValue: cfg.PasskeyName, Default: "Passkey",
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
	ev := &mailpb.SendPasskeyAddedEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(email)
	ev.SetLocale(locale)
	ev.SetPasskeyName(passkeyName)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	payload, err := proto.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	if err := ps.Publish(topics.TopicPasskeyAdded, payload); err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	log.Printf(
		"published topic=%s email=%s locale=%s passkey=%s bytes=%d",
		topics.TopicPasskeyAdded, email, locale, passkeyName, len(payload),
	)
	return nil
}
