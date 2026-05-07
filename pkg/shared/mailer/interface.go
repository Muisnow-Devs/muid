package mailer

import "context"

type Message struct {
	To      []string
	CC      []string
	BCC     []string
	ReplyTo []string

	Subject string

	TextBody string
	HTMLBody string

	Headers     map[string]string
	Attachments []Attachment
}

type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

type Mailer interface {
	Send(ctx context.Context, msg Message) error
}
