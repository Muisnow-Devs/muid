package entpostgres

import (
	"context"
	"errors"
	"testing"

	"entgo.io/ent/dialect/sql/schema"
)

type fakeSchema struct {
	err error
}

func (f *fakeSchema) Create(ctx context.Context, opts ...schema.MigrateOption) error {
	return f.err
}

func TestSchemaCreateBestEffort_nil(t *testing.T) {
	ctx := context.Background()
	if err := SchemaCreateBestEffort(ctx, &fakeSchema{err: nil}, "test: "); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaCreateBestEffort_idempotentMessages(t *testing.T) {
	ctx := context.Background()
	cases := []string{
		"relation \"users\" already exists",
		"duplicate key value violates unique constraint",
		"DUPLICATE object",
	}
	for _, msg := range cases {
		err := SchemaCreateBestEffort(ctx, &fakeSchema{err: errors.New(msg)}, "test: ")
		if err != nil {
			t.Fatalf("msg=%q: %v", msg, err)
		}
	}
}

func TestSchemaCreateBestEffort_hardFailure(t *testing.T) {
	ctx := context.Background()
	root := errors.New("connection reset")
	err := SchemaCreateBestEffort(ctx, &fakeSchema{err: root}, "test: ")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrSchemaCreate) {
		t.Fatalf("errors.Is(ErrSchemaCreate): got %v", err)
	}
	if !errors.Is(err, root) {
		t.Fatalf("errors.Is(root): got %v", err)
	}
}
