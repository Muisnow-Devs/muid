// Package enttx wraps ent Client.Tx commit/rollback boilerplate (defer Rollback, Commit on success).
package enttx

import (
	"context"

	"sanzi.io/muid/pkg/errutil"
	"sanzi.io/muid/pkg/shared/tracing"
)

// Transaction is the commit/rollback surface shared by generated *ent.Tx types.
type Transaction interface {
	Commit() error
	Rollback() error
}

// Run begins a transaction via begin, executes fn, commits when fn returns nil, and always
// attempts Rollback on exit (ent ignores Rollback after a successful Commit). Uses the same
// ctx for begin, fn, and the underlying ent transaction (context cancellation semantics unchanged).
func Run[T any, X Transaction](
	ctx context.Context,
	begin func(context.Context) (X, error),
	fn func(context.Context, X) (T, error),
) (T, error) {
	spanName := "ent.tx"
	if name, ok := tracing.SpanNameFromContext(ctx); ok {
		spanName = name
	}
	ctx, span := tracing.StartSpan(ctx, spanName)
	defer span.End()

	tx, err := begin(ctx)
	if err != nil {
		span.RecordError(err)
		var zero T
		return zero, err
	}
	defer func() { errutil.Discard(tx.Rollback()) }()

	result, err := fn(ctx, tx)
	if err != nil {
		span.RecordError(err)
		var zero T
		return zero, err
	}

	err = tx.Commit()
	if err != nil {
		span.RecordError(err)
		var zero T
		return zero, err
	}
	return result, nil
}

// Do is Run for callbacks that only return an error.
func Do[X Transaction](
	ctx context.Context,
	begin func(context.Context) (X, error),
	fn func(context.Context, X) error,
) error {
	_, err := Run(ctx, begin, func(ctx context.Context, tx X) (struct{}, error) {
		return struct{}{}, fn(ctx, tx)
	})
	return err
}
