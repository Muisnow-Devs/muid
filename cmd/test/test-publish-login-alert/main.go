package main

import (
	"fmt"
	"log"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/infra/nats"
	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/shared"
	"sanzi.io/muid/pkg/shared/topics"
)

const configEnvPrefix = "TEST_PUBLISH_LOGIN_ALERT"

type config struct {
	NATSURL    string `envconfig:"NATS_URL" required:"true"`
	Email      string `envconfig:"EMAIL" required:"true"`
	Locale     string `envconfig:"LOCALE" default:"en"`
	IPAddress  string `envconfig:"IP_ADDRESS" default:"203.0.113.1"`
	Location   string `envconfig:"LOCATION" default:"Taipei, TW"`
	Device     string `envconfig:"DEVICE" default:"Chrome on Windows"`
	UserAgent  string `envconfig:"USER_AGENT" default:"Mozilla/5.0 (test-publish-login-alert)"`
	SecureLink string `envconfig:"SECURE_LINK" default:"https://example.com/account/security"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("publish login alert event: %v", err)
	}
}

func run() error {
	cfg, err := shared.LoadConfig[config](configEnvPrefix)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	ps, err := nats.NewNATSPubSub(cfg.NATSURL)
	if err != nil {
		return fmt.Errorf("connect nats: %w", err)
	}
	defer errutil.CloseIf(ps)

	now := time.Now().UTC()

	ev := &mailpb.SendLoginAlertEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(cfg.Email)
	ev.SetLocale(cfg.Locale)
	ev.SetIpAddress(cfg.IPAddress)
	ev.SetLocation(cfg.Location)
	ev.SetDevice(cfg.Device)
	ev.SetUserAgent(cfg.UserAgent)
	ev.SetSecureLink(cfg.SecureLink)
	ev.SetOccurredAt(timestamppb.New(now))
	ev.SetCreatedAt(timestamppb.New(now))

	payload, err := proto.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	if err := ps.Publish(topics.TopicSendLoginAlert, payload); err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	log.Printf("published topic=%s email=%s bytes=%d", topics.TopicSendLoginAlert, cfg.Email, len(payload))
	return nil
}
