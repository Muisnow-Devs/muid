package app

const ConfigEnvPrefix = "MAILER"

type Config struct {
	Debug bool `envconfig:"DEBUG" default:"false"`

	NATSURL string `envconfig:"NATS_URL" required:"true"`

	SMTPHost     string `envconfig:"SMTP_HOST"     required:"true"`
	SMTPPort     int    `envconfig:"SMTP_PORT"                     default:"587"`
	SMTPFrom     string `envconfig:"SMTP_FROM"     required:"true"`
	SMTPUsername string `envconfig:"SMTP_USERNAME"                 default:""`
	SMTPPassword string `envconfig:"SMTP_PASSWORD"                 default:""`
}
