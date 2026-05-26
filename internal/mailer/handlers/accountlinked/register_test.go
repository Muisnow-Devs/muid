package accountlinked

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
	"sanzi.io/muid/pkg/shared/topics"
)

type stubAccountLinkedRenderer struct {
	got handlers.TopicAccountLinked
}

func (s *stubAccountLinkedRenderer) Render(
	_ context.Context,
	_ string,
	_ string,
	data any,
) (*templates.RenderedMail, error) {
	s.got = data.(handlers.TopicAccountLinked)
	return &templates.RenderedMail{
		Subject: "account linked",
		Text:    "provider=" + s.got.Provider + " time=" + s.got.Time,
		HTML:    "<p>provider=" + s.got.Provider + " time=" + s.got.Time + "</p>",
	}, nil
}

func TestHandler_topic(t *testing.T) {
	t.Parallel()

	if (Handler{}).Topic() != topics.TopicAccountLinked {
		t.Fatalf("Topic() = %q, want %q", (Handler{}).Topic(), topics.TopicAccountLinked)
	}
}

func TestHandler_rendersEventDerivedFields(t *testing.T) {
	t.Parallel()

	occurred := time.Date(2026, 5, 25, 6, 30, 0, 0, time.UTC)
	ev := &mailpb.SendAccountLinkedEmailEvent{}
	ev.SetEmail("user@example.com")
	ev.SetLocale("en")
	ev.SetTimezone("UTC")
	ev.SetProvider("google")
	ev.SetOccurredAt(timestamppb.New(occurred))

	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	renderer := &stubAccountLinkedRenderer{}
	msg, err := Handler{}.Handle(context.Background(), renderer, payload)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}

	if msg.To[0] != "user@example.com" {
		t.Fatalf("to: %v", msg.To)
	}
	if renderer.got.Provider != "google" {
		t.Fatalf("provider: %q", renderer.got.Provider)
	}
	if renderer.got.Time == "" {
		t.Fatal("expected formatted time")
	}
	if msg.Subject == "" || msg.TextBody == "" || msg.HTMLBody == "" {
		t.Fatalf("expected non-empty message parts: %#v", msg)
	}
	if !strings.Contains(msg.TextBody, "provider=google") {
		t.Fatalf("text body: %q", msg.TextBody)
	}
}

func TestHandler_localeFallbackToEnglish(t *testing.T) {
	t.Parallel()

	ev := &mailpb.SendAccountLinkedEmailEvent{}
	ev.SetEmail("user@example.com")
	ev.SetLocale("fr")
	ev.SetTimezone("UTC")
	ev.SetProvider("google")
	ev.SetOccurredAt(timestamppb.New(time.Now().UTC()))

	payload, err := proto.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	loader := templates.NewTemplateLoader(
		templates.HTMLTemplatesFS,
		templates.TextTemplatesFS,
		templates.LocaleTemplateFS,
	)

	msg, err := Handler{}.Handle(context.Background(), loader, payload)
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if msg.Subject == "" || msg.TextBody == "" || msg.HTMLBody == "" {
		t.Fatalf("expected non-empty message parts: %#v", msg)
	}
	if !strings.Contains(msg.Subject, "[MuID]") {
		t.Fatalf("subject: %q", msg.Subject)
	}
}

