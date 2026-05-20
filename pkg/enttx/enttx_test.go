package enttx_test

import (
	"context"
	"errors"
	"testing"

	"sanzi.io/muid/pkg/enttx"
)

type fakeTx struct {
	committed  bool
	rolledBack bool
	commitErr  error
}

func (f *fakeTx) Commit() error {
	if f.commitErr != nil {
		return f.commitErr
	}
	f.committed = true
	return nil
}

func (f *fakeTx) Rollback() error {
	f.rolledBack = true
	return nil
}

func TestRun(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	errBegin := errors.New("begin failed")
	errFn := errors.New("fn failed")
	errCommit := errors.New("commit failed")

	tests := []struct {
		name    string
		begin   func(context.Context) (*fakeTx, error)
		fn      func(context.Context, *fakeTx) (string, error)
		want    string
		wantErr error
		check   func(t *testing.T, tx *fakeTx)
	}{
		{
			name: "begin error",
			begin: func(context.Context) (*fakeTx, error) {
				return nil, errBegin
			},
			fn: func(context.Context, *fakeTx) (string, error) {
				return "ok", nil
			},
			wantErr: errBegin,
		},
		{
			name: "fn error rolls back without commit",
			begin: func(context.Context) (*fakeTx, error) {
				return &fakeTx{}, nil
			},
			fn: func(context.Context, *fakeTx) (string, error) {
				return "", errFn
			},
			wantErr: errFn,
			check: func(t *testing.T, tx *fakeTx) {
				t.Helper()
				if tx.committed {
					t.Fatal("committed after fn error")
				}
				if !tx.rolledBack {
					t.Fatal("expected rollback")
				}
			},
		},
		{
			name: "commit error",
			begin: func(context.Context) (*fakeTx, error) {
				return &fakeTx{commitErr: errCommit}, nil
			},
			fn: func(context.Context, *fakeTx) (string, error) {
				return "ok", nil
			},
			wantErr: errCommit,
			check: func(t *testing.T, tx *fakeTx) {
				t.Helper()
				if tx.committed {
					t.Fatal("committed despite commit error")
				}
				if !tx.rolledBack {
					t.Fatal("expected rollback")
				}
			},
		},
		{
			name: "success commits then defer rollback",
			begin: func(context.Context) (*fakeTx, error) {
				return &fakeTx{}, nil
			},
			fn: func(context.Context, *fakeTx) (string, error) {
				return "done", nil
			},
			want: "done",
			check: func(t *testing.T, tx *fakeTx) {
				t.Helper()
				if !tx.committed {
					t.Fatal("expected commit")
				}
				if !tx.rolledBack {
					t.Fatal("expected defer rollback")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var captured *fakeTx
			begin := func(c context.Context) (*fakeTx, error) {
				tx, err := tt.begin(c)
				captured = tx
				return tx, err
			}

			got, err := enttx.Run(ctx, begin, tt.fn)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Run() err = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("Run() = %q, want %q", got, tt.want)
			}
			if tt.check != nil {
				if captured == nil {
					t.Fatal("missing tx instance for check")
				}
				tt.check(t, captured)
			}
		})
	}
}

func TestDo(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	tx := &fakeTx{}

	err := enttx.Do(ctx, func(context.Context) (*fakeTx, error) {
		return tx, nil
	}, func(context.Context, *fakeTx) error {
		return nil
	})
	if err != nil {
		t.Fatalf("Do() err = %v", err)
	}
	if !tx.committed || !tx.rolledBack {
		t.Fatalf("committed=%v rolledBack=%v", tx.committed, tx.rolledBack)
	}
}
