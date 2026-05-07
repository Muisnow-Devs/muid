package topics

type MailTopic = Topic

const (
	TopicSendNotSpecifiedEmail MailTopic = "mail.send.email"
	TopicSendOTP               MailTopic = "mail.send.otp"
	TopicSendLoginAlert        MailTopic = "mail.send.login_alert"
)
