package topics

type ProfileTopic = Topic

const (
	// TopicProfileChange carries protobuf muid.event.v1.profile.ProfileChangedEvent.
	TopicProfileChange ProfileTopic = "profile.change"
)
