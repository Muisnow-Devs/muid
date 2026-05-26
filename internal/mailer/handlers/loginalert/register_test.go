package loginalert

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	mailpb "sanzi.io/muid/api/proto/event/v1/mail"
	"sanzi.io/muid/internal/mailer/handlers"
	"sanzi.io/muid/internal/templates"
)

type stubLoginAlertRenderer struct {
	got handlers.TopicLoginAlert
}

func (s *stubLoginAlertRenderer) Render(
	_ context.Context,
	_ string,
	_ string,
	data any,
) (*templates.RenderedMail, error) {
	s.got = data.(handlers.TopicLoginAlert)
	return &templates.RenderedMail{
		Subject: "login alert",
		Text:    s.got.Device,
		HTML:    "<p>" + s.got.Device + "</p>",
	}, nil
}

func TestHandler_rendersTransitionDerivedFields(t *testing.T) {
	t.Parallel()

	occurred := time.Date(2026, 5, 25, 6, 30, 0, 0, time.UTC)
	ev := &mailpb.SendLoginAlertEmailEvent{}
	ev.SetEmail("user@example.com")
	ev.SetLocale("en")
	ev.SetTimezone("UTC")
	ev.SetDevice("Chrome on Windows")
	ev.SetLocation("Taipei, TW")
	ev.SetIpAddress("203.0.113.1")
	ev.SetSecureLink("https://example.com/security")
	ev.SetOccurredAt(timestamppb.New(occurred))

	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	renderer := &stubLoginAlertRenderer{}
	msg, err := Handler{}.Handle(context.Background(), renderer, payload)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if msg.To[0] != "user@example.com" {
		t.Fatalf("to: %v", msg.To)
	}
	if renderer.got.Device != "Chrome on Windows" || renderer.got.Location != "Taipei, TW" {
		t.Fatalf("render data: %+v", renderer.got)
	}
	if renderer.got.IPAddress != "203.0.113.1" {
		t.Fatalf("ip: %q", renderer.got.IPAddress)
	}
	if renderer.got.SecureAccountLink != "https://example.com/security" {
		t.Fatalf("secure link: %q", renderer.got.SecureAccountLink)
	}
	if renderer.got.Time == "" {
		t.Fatal("expected formatted time")
	}
	if !strings.Contains(msg.TextBody, "Chrome on Windows") {
		t.Fatalf("text body: %q", msg.TextBody)
	}
}
