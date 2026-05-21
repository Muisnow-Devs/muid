package signature

import (
	"context"
	"time"
)

type rotationTicker interface {
	C() <-chan time.Time
	Stop()
}

type realRotationTicker struct {
	ticker *time.Ticker
}

func (t realRotationTicker) C() <-chan time.Time {
	return t.ticker.C
}

func (t realRotationTicker) Stop() {
	t.ticker.Stop()
}

type rotationJob struct {
	period     time.Duration
	newTicker  func(time.Duration) rotationTicker
	rotate     func(context.Context) error
	logFailure func(context.Context, error)
}

func (j rotationJob) run(ctx context.Context) {
	if j.period <= 0 {
		return
	}

	newTicker := j.newTicker
	if newTicker == nil {
		newTicker = func(period time.Duration) rotationTicker {
			return realRotationTicker{ticker: time.NewTicker(period)}
		}
	}

	ticker := newTicker(j.period)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			err := j.rotate(ctx)
			if err == nil {
				continue
			}
			if j.logFailure != nil {
				j.logFailure(ctx, err)
			}
		}
	}
}
