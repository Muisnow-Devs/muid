package templates

import "testing"

func TestLoad(t *testing.T) {
	loader := NewTemplateLoader(TemplatesFS)

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

		t.Log("Parsed result:", tmpl)
	})
}
