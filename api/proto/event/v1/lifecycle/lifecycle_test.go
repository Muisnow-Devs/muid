package lifecycleevent

import (
	"testing"

	"buf.build/go/protovalidate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestLifecycleEventValidation(t *testing.T) {
	t.Parallel()

	validator, err := protovalidate.New()
	if err != nil {
		t.Fatal(err)
	}

	validAccount := func() *AccountRegistered {
		event := &AccountRegistered{}
		event.SetEventId("11111111-1111-4111-8111-111111111111")
		event.SetUserId("22222222-2222-4222-8222-222222222222")
		event.SetOccurredAt(timestamppb.Now())
		return event
	}
	validOrganization := func() *OrganizationCreated {
		event := &OrganizationCreated{}
		event.SetEventId("33333333-3333-4333-8333-333333333333")
		event.SetOrganizationId("44444444-4444-4444-8444-444444444444")
		event.SetDisplayName("Example organization")
		event.SetOccurredAt(timestamppb.Now())
		return event
	}

	tests := []struct {
		name  string
		event proto.Message
		valid bool
	}{
		{
			name:  "organization permits empty requested slug",
			event: validOrganization(),
			valid: true,
		},
		{
			name: "organization rejects malformed slug",
			event: func() proto.Message {
				event := validOrganization()
				event.SetSlug("Not valid")
				return event
			}(),
		},
		{
			name: "account rejects malformed event UUID",
			event: func() proto.Message {
				event := validAccount()
				event.SetEventId("not-a-uuid")
				return event
			}(),
		},
		{
			name: "account rejects malformed user UUID",
			event: func() proto.Message {
				event := validAccount()
				event.SetUserId("not-a-uuid")
				return event
			}(),
		},
		{
			name: "organization rejects malformed event UUID",
			event: func() proto.Message {
				event := validOrganization()
				event.SetEventId("not-a-uuid")
				return event
			}(),
		},
		{
			name: "organization rejects malformed organization UUID",
			event: func() proto.Message {
				event := validOrganization()
				event.SetOrganizationId("not-a-uuid")
				return event
			}(),
		},
		{
			name: "account requires occurred at",
			event: func() proto.Message {
				event := validAccount()
				event.ClearOccurredAt()
				return event
			}(),
		},
		{
			name: "organization requires occurred at",
			event: func() proto.Message {
				event := validOrganization()
				event.ClearOccurredAt()
				return event
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validator.Validate(tt.event)
			if (err == nil) != tt.valid {
				t.Errorf("Validate() error = %v, want valid = %t", err, tt.valid)
			}
		})
	}
}
