package templates

import "context"

// MailRenderer renders localized HTML/text mail bodies and subjects from embedded templates.
type MailRenderer interface {
	Render(ctx context.Context, locale, page string, data any) (*RenderedMail, error)
}
