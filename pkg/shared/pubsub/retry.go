package pubsub

import (
	"errors"
	"math"
	"strconv"
	"time"
)

const (
	RetryMaxAttemptsHeader       = "X-Muid-Retry-Max-Attempts"
	RetryInitialDelayHeader      = "X-Muid-Retry-Initial-Delay"
	RetryMaxDelayHeader          = "X-Muid-Retry-Max-Delay"
	RetryBackoffMultiplierHeader = "X-Muid-Retry-Backoff-Multiplier"
)

var ErrNonRetryable = errors.New("pubsub: non-retryable message failure")

type HeaderCarrier interface {
	Get(key string) string
	Set(key, value string)
}

// RetryPolicy describes how a failed message should be redelivered.
type RetryPolicy struct {
	MaxAttempts       int
	InitialDelay      time.Duration
	MaxDelay          time.Duration
	BackoffMultiplier float64
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       3,
		InitialDelay:      5 * time.Second,
		MaxDelay:          time.Minute,
		BackoffMultiplier: 2,
	}
}

func CriticalRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:       5,
		InitialDelay:      10 * time.Second,
		MaxDelay:          5 * time.Minute,
		BackoffMultiplier: 2,
	}
}

func (p RetryPolicy) WithDefaults() RetryPolicy {
	defaults := DefaultRetryPolicy()
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = defaults.MaxAttempts
	}
	if p.InitialDelay <= 0 {
		p.InitialDelay = defaults.InitialDelay
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = defaults.MaxDelay
	}
	if p.BackoffMultiplier < 1 {
		p.BackoffMultiplier = defaults.BackoffMultiplier
	}
	if p.MaxDelay < p.InitialDelay {
		p.MaxDelay = p.InitialDelay
	}
	return p
}

// DelayForAttempt returns the delay before the next delivery after deliveryAttempt failed.
func (p RetryPolicy) DelayForAttempt(deliveryAttempt uint64) time.Duration {
	p = p.WithDefaults()
	if deliveryAttempt <= 1 {
		return p.InitialDelay
	}

	multiplier := math.Pow(p.BackoffMultiplier, float64(deliveryAttempt-1))
	delay := time.Duration(float64(p.InitialDelay) * multiplier)
	if delay <= 0 || delay > p.MaxDelay {
		return p.MaxDelay
	}
	return delay
}

func (p RetryPolicy) BackoffSchedule() []time.Duration {
	p = p.WithDefaults()
	if p.MaxAttempts <= 1 {
		return nil
	}

	backoff := make([]time.Duration, 0, p.MaxAttempts-1)
	for attempt := 1; attempt < p.MaxAttempts; attempt++ {
		backoff = append(backoff, p.DelayForAttempt(uint64(attempt)))
	}
	return backoff
}

func EncodeRetryPolicyHeaders(headers HeaderCarrier, policy RetryPolicy) {
	policy = policy.WithDefaults()
	headers.Set(RetryMaxAttemptsHeader, strconv.Itoa(policy.MaxAttempts))
	headers.Set(RetryInitialDelayHeader, policy.InitialDelay.String())
	headers.Set(RetryMaxDelayHeader, policy.MaxDelay.String())
	headers.Set(
		RetryBackoffMultiplierHeader,
		strconv.FormatFloat(policy.BackoffMultiplier, 'f', -1, 64),
	)
}

func DecodeRetryPolicyHeaders(headers HeaderCarrier) (RetryPolicy, bool, error) {
	if headers == nil || headers.Get(RetryMaxAttemptsHeader) == "" {
		return DefaultRetryPolicy(), false, nil
	}

	maxAttempts, err := strconv.Atoi(headers.Get(RetryMaxAttemptsHeader))
	if err != nil {
		return RetryPolicy{}, true, err
	}
	initialDelay, err := time.ParseDuration(headers.Get(RetryInitialDelayHeader))
	if err != nil {
		return RetryPolicy{}, true, err
	}
	maxDelay, err := time.ParseDuration(headers.Get(RetryMaxDelayHeader))
	if err != nil {
		return RetryPolicy{}, true, err
	}
	multiplier, err := strconv.ParseFloat(headers.Get(RetryBackoffMultiplierHeader), 64)
	if err != nil {
		return RetryPolicy{}, true, err
	}

	return RetryPolicy{
		MaxAttempts:       maxAttempts,
		InitialDelay:      initialDelay,
		MaxDelay:          maxDelay,
		BackoffMultiplier: multiplier,
	}.WithDefaults(), true, nil
}
