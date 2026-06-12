package topics

type AuthzTopic = Topic

const (
	// TopicAuthzPolicyChanged carries protobuf muid.event.v1.authz.PolicyChangedEvent.
	TopicAuthzPolicyChanged AuthzTopic = "authz.policy.changed"
)
