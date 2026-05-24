package templates

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestValidateTemplateSegment(t *testing.T) {
	t.Parallel()

	ok := []string{"en", "zh-TW", "otp", "login_alert", "page_v2"}
	for _, s := range ok {
		if err := validateTemplateSegment(s, "segment"); err != nil {
			t.Errorf("validateTemplateSegment(%q) = %v; want nil", s, err)
		}
	}

	bad := []struct {
		in   string
		desc string
	}{
		{"", "empty"},
		{".", "dot"},
		{"..", "dotdot"},
		{"../x", "parent prefix"},
		{"x/../y", "parent infix"},
		{"x/..", "parent suffix"},
		{"locale/../../etc", "slashes and dots"},
		{"a\\b", "backslash"},
		{"a/b", "slash"},
		{"en\x00", "nul"},
		{"..\\otp", "windows-ish"},
	}
	for _, tc := range bad {
		err := validateTemplateSegment(tc.in, "segment")
		if err == nil {
			t.Fatalf("validateTemplateSegment(%q) (%s): want error", tc.in, tc.desc)
		}

		if !errors.Is(err, ErrInvalidTemplatePath) {
			t.Fatalf("validateTemplateSegment(%q): %v missing ErrInvalidTemplatePath", tc.in, err)
		}
	}
}

func TestRender_templatePathValidation(t *testing.T) {
	t.Parallel()

	loader := NewTemplateLoader(HTMLTemplatesFS, TextTemplatesFS, LocaleTemplateFS)
	ctx := context.Background()

	otpData := struct {
		ExpiryTime string
		OTP        string
	}{
		ExpiryTime: "5 minutes",
		OTP:        "123456",
	}

	loginAlertData := struct {
		Device            string
		Location          string
		IPAddress         string
		Time              string
		SecureAccountLink string
	}{
		Device:            "Chrome on Windows",
		Location:          "Taiwan",
		IPAddress:         "127.0.0.1",
		Time:              "now",
		SecureAccountLink: "https://example.com/account",
	}

	passkeyAddedData := struct {
		PasskeyName string
		Time        string
	}{
		PasskeyName: "MacBook Touch ID",
		Time:        "now",
	}

	t.Run("benign locale and page succeed", func(t *testing.T) {
		t.Parallel()

		_, err := loader.Render(ctx, "en", "otp", otpData)
		if err != nil {
			t.Fatalf("Render(en, otp): %v", err)
		}

		_, err = loader.Render(ctx, "zh-TW", "login_alert", loginAlertData)
		if err != nil {
			t.Fatalf("Render(zh-TW, login_alert): %v", err)
		}

		_, err = loader.Render(ctx, "en", "passkey_added", passkeyAddedData)
		if err != nil {
			t.Fatalf("Render(en, passkey_added): %v", err)
		}
	})

	traversalLocales := []string{
		"../en",
		"en/../evil",
		"locale/../../etc",
		"..\\en",
		"en\x00",
	}
	for _, loc := range traversalLocales {
		loc := loc

		t.Run("reject locale "+loc, func(t *testing.T) {
			t.Parallel()

			_, err := loader.Render(ctx, loc, "otp", otpData)
			if err == nil {
				t.Fatal("expected error")
			}

			if !errors.Is(err, ErrInvalidTemplatePath) {
				t.Fatalf("errors.Is: got %v", err)
			}
		})
	}

	traversalPages := []string{
		"../otp",
		"otp/../../etc",
		"..\\otp",
		"otp\x00",
	}
	for _, page := range traversalPages {
		page := page

		t.Run("reject page "+page, func(t *testing.T) {
			t.Parallel()

			_, err := loader.Render(ctx, "en", page, otpData)
			if err == nil {
				t.Fatal("expected error")
			}

			if !errors.Is(err, ErrInvalidTemplatePath) {
				t.Fatalf("errors.Is: got %v", err)
			}
		})
	}
}

func TestRenderEmailChangedChineseKeepsTimeInTimeSlot(t *testing.T) {
	t.Parallel()

	loader := NewTemplateLoader(HTMLTemplatesFS, TextTemplatesFS, LocaleTemplateFS)
	ctx := context.Background()
	rendered, err := loader.Render(ctx, "zh-TW", "email_changed", struct {
		OldEmail string
		NewEmail string
		Time     string
	}{
		OldEmail: "old@example.com",
		NewEmail: "new@example.com",
		Time:     "2026-05-25 14:30:05 +0800",
	})
	if err != nil {
		t.Fatalf("Render(zh-TW, email_changed): %v", err)
	}

	wantDescription := "您的帳號電子郵件已於 2026-05-25 14:30:05 +0800 變更。"
	for _, body := range []string{rendered.Text, rendered.HTML} {
		if !strings.Contains(body, wantDescription) {
			t.Fatalf("rendered body missing description %q: %q", wantDescription, body)
		}
	}

	for _, want := range []string{"原電子郵件：", "old@example.com", "新電子郵件：", "new@example.com"} {
		if !strings.Contains(rendered.HTML, want) {
			t.Fatalf("HTML missing %q: %q", want, rendered.HTML)
		}
	}
}
