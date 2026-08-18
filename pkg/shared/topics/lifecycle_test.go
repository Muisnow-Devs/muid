package topics

import "testing"

func TestLifecycleTopics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		topic Topic
		want  string
	}{
		{
			name:  "account registered",
			topic: TopicAccountRegistered,
			want:  "account.registered",
		},
		{
			name:  "organization created",
			topic: TopicOrganizationCreated,
			want:  "organization.created",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := string(tt.topic); got != tt.want {
				t.Errorf("topic = %q, want %q", got, tt.want)
			}
		})
	}
}
