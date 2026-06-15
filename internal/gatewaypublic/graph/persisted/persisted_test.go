package persisted

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/99designs/gqlgen/graphql"
)

func TestLoadApolloManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	manifest := `{
	  "format": "apollostandard",
	  "version": 1,
	  "operations": [
	    {"id": "abc", "body": "query { health { status } }"},
	    {"id": "", "body": "ignored"},
	    {"id": "def", "body": ""}
	  ]
	}`
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	docs, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(docs) != 1 || docs["abc"] != "query { health { status } }" {
		t.Fatalf("unexpected docs: %v", docs)
	}
}

func TestLoadBlankPath(t *testing.T) {
	t.Parallel()

	docs, err := Load("")
	if err != nil {
		t.Fatalf("Load blank: %v", err)
	}
	if len(docs) != 0 {
		t.Fatalf("expected empty docs, got %v", docs)
	}
}

func TestValidateEmptyAllowlistFailsInProduction(t *testing.T) {
	t.Parallel()

	if err := New(nil, false).Validate(nil); err == nil {
		t.Fatalf("expected empty production allowlist to fail validation")
	}
	if err := New(nil, true).Validate(nil); err != nil {
		t.Fatalf("debug mode should tolerate an empty allowlist: %v", err)
	}
}

func TestMutateProductionRejectsRawAndUnknown(t *testing.T) {
	t.Parallel()

	ops := New(map[string]string{"known": "query { health { status } }"}, false)

	// Raw query rejected.
	raw := &graphql.RawParams{Query: "query { health { status } }"}
	if err := ops.MutateOperationParameters(context.Background(), raw); err == nil {
		t.Fatalf("expected raw query rejection")
	}

	// Unknown hash rejected.
	unknown := &graphql.RawParams{Extensions: map[string]any{"persistedQuery": map[string]any{"sha256Hash": "nope"}}}
	if err := ops.MutateOperationParameters(context.Background(), unknown); err == nil {
		t.Fatalf("expected unknown hash rejection")
	}

	// Known hash resolves to its document.
	known := &graphql.RawParams{Extensions: map[string]any{"persistedQuery": map[string]any{"sha256Hash": "known"}}}
	if err := ops.MutateOperationParameters(context.Background(), known); err != nil {
		t.Fatalf("known hash should resolve: %v", err)
	}
	if known.Query != "query { health { status } }" {
		t.Fatalf("query not populated from manifest: %q", known.Query)
	}
}
