package topics

type AuthTopic = Topic

const (
	TopicAuthStarted    AuthTopic = "auth.started"
	TopicAuthFailed     AuthTopic = "auth.failed"
	TopicAuthCompleted  AuthTopic = "auth.completed"
	TopicSessionCreated AuthTopic = "auth.session.created"
	TopicSessionRevoked AuthTopic = "auth.session.revoked"

	// Refresh token events
	TopicRefreshTokenCreated AuthTopic = "auth.refresh_token.created"
	TopicRefreshTokenRotated AuthTopic = "auth.refresh_token.rotated"
	TopicRefreshTokenRevoked AuthTopic = "auth.refresh_token.revoked"
	TopicRefreshTokenExpired AuthTopic = "auth.refresh_token.expired"
	TopicRefreshTokenReused  AuthTopic = "auth.refresh_token.reused"
)
