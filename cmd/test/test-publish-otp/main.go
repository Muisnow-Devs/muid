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

const configEnvPrefix = "TEST_PUBLISH_OTP"

type config struct {
	NATSURL        string `envconfig:"NATS_URL" required:"true"`
	Email          string `envconfig:"EMAIL" required:"true"`
	Locale         string `envconfig:"LOCALE" default:"en"`
	Code           string `envconfig:"CODE" default:"123456"`
	ExpiresSeconds int    `envconfig:"EXPIRES_SECONDS" default:"300"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("publish otp event: %v", err)
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
	expires := now.Add(time.Duration(cfg.ExpiresSeconds) * time.Second)

	ev := &mailpb.SendOTPEmailEvent{}
	ev.SetId(shared.UUIDV7().String())
	ev.SetEmail(cfg.Email)
	ev.SetLocale(cfg.Locale)
	ev.SetCode(cfg.Code)
	ev.SetExpiresAt(timestamppb.New(expires))
	ev.SetCreatedAt(timestamppb.New(now))

	payload, err := proto.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}

	if err := ps.Publish(topics.TopicSendOTP, payload); err != nil {
		return fmt.Errorf("publish: %w", err)
	}

	log.Printf("published topic=%s email=%s bytes=%d", topics.TopicSendOTP, cfg.Email, len(payload))
	return nil
}
