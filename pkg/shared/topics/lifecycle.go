package topics

type LifecycleTopic = Topic

const (
	// TopicAccountRegistered carries lifecycleevent.AccountRegistered.
	TopicAccountRegistered LifecycleTopic = "account.registered"
	// TopicOrganizationCreated carries lifecycleevent.OrganizationCreated.
	TopicOrganizationCreated LifecycleTopic = "organization.created"
)
