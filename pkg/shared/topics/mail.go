package topics

type MailTopic = Topic

const (
	TopicSendNotSpecifiedEmail MailTopic = "mail.send.email"
	TopicSendOTP               MailTopic = "mail.send.otp"
	TopicSendLoginAlert        MailTopic = "mail.send.login_alert"
	TopicEmailChanged          MailTopic = "mail.send.email_changed"
	TopicPasskeyAdded          MailTopic = "mail.send.passkey_added"
	TopicPasskeyRemoved        MailTopic = "mail.send.passkey_removed"
	TopicAccountLinked         MailTopic = "mail.send.account_linked"

	TopicOIDCClientGranted MailTopic = "mail.oidc.client_granted"
)
