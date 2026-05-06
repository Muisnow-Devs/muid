package templates

import (
	"testing"
)

func TestLoad(t *testing.T) {
	loader := NewTemplateLoader(HTMLTemplatesFS, TextTemplatesFS, LocaleTemplateFS)

	t.Run("Load existing template", func(t *testing.T) {
		tmpl, err := loader.Render("en", "otp", struct {
			ExpiryTime string
			OTP        string
		}{
			ExpiryTime: "5 minutes",
			OTP:        "123456",
		})

		if err != nil {
			t.Fatalf("Failed to load template: %v", err)
		}

		t.Log("Parsed HTML Template:", tmpl.HTML)
		t.Log("Parsed Text Template:", tmpl.Text)
		t.Log("Parsed Subject Template:", tmpl.Subject)
	})
}
