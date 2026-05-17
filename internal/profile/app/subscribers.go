package app

import (
	"context"

	"sanzi.io/muid/internal/profile/subscriber"
)

func registerSubscribers(ctx context.Context, infra *InfraDependencies) error {
	return subscriber.Register(ctx, infra.PubSub, infra.Ent)
}
