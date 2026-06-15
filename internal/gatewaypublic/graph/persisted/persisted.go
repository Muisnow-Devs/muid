// Package persisted implements a gqlgen extension that restricts the public
// gateway to a pre-registered set of GraphQL operations ("trusted documents").
//
// In production the gateway is the untrusted-internet edge: clients may only
// invoke operations whose sha256 hash appears in the manifest (the same
// Apollo-style persisted-query protocol used by Apollo Client / graphql-codegen
// persisted documents). Ad-hoc queries and unknown hashes are rejected, and
// introspection stays off. In debug mode the extension is permissive so the
// schema can be explored with arbitrary operations.
package persisted

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/errcode"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	errNotInAllowlist     = "operation is not in the persisted-operations allowlist"
	errNotInAllowlistCode = "PERSISTED_QUERY_NOT_FOUND"
)

// ErrEmptyManifest is returned when a manifest path resolves to zero operations.
var ErrEmptyManifest = errors.New("persisted-operations manifest is empty")

// Operations is an immutable hash→document allowlist.
type Operations struct {
	// allowRaw permits arbitrary queries and unknown hashes (debug only).
	allowRaw bool
	docs     map[string]string
}

var _ interface {
	graphql.OperationParameterMutator
	graphql.HandlerExtension
} = Operations{}

// New builds an Operations extension. When allowRaw is true the extension is
// permissive (development); otherwise docs is the strict allowlist.
func New(docs map[string]string, allowRaw bool) Operations {
	return Operations{allowRaw: allowRaw, docs: docs}
}

// ExtensionName implements graphql.HandlerExtension.
func (Operations) ExtensionName() string { return "PersistedOperations" }

// Validate implements graphql.HandlerExtension.
func (o Operations) Validate(graphql.ExecutableSchema) error {
	if !o.allowRaw && len(o.docs) == 0 {
		return ErrEmptyManifest
	}
	return nil
}

// MutateOperationParameters resolves a persisted hash into its query document
// and enforces the allowlist. The hash is supplied via the standard persisted-
// query extension: extensions.persistedQuery.sha256Hash.
func (o Operations) MutateOperationParameters(_ context.Context, rawParams *graphql.RawParams) *gqlerror.Error {
	hash := persistedHash(rawParams)

	if o.allowRaw {
		// Development: resolve known hashes if provided, otherwise let the raw
		// query (or APQ miss) flow through untouched.
		if hash != "" && rawParams.Query == "" {
			if doc, ok := o.docs[hash]; ok {
				rawParams.Query = doc
			}
		}
		return nil
	}

	// Production: the only accepted shape is a known hash with no inline query.
	if rawParams.Query != "" {
		return notAllowed()
	}
	if hash == "" {
		return notAllowed()
	}
	doc, ok := o.docs[hash]
	if !ok {
		return notAllowed()
	}
	rawParams.Query = doc
	return nil
}

func notAllowed() *gqlerror.Error {
	err := gqlerror.Errorf(errNotInAllowlist)
	errcode.Set(err, errNotInAllowlistCode)
	return err
}

// persistedHash extracts extensions.persistedQuery.sha256Hash, if present.
func persistedHash(rawParams *graphql.RawParams) string {
	pq, ok := rawParams.Extensions["persistedQuery"].(map[string]any)
	if !ok {
		return ""
	}
	h, _ := pq["sha256Hash"].(string)
	return h
}

// apolloManifest is the Apollo persisted-query manifest shape (also emitted by
// graphql-codegen's persisted-documents plugin).
type apolloManifest struct {
	Operations []struct {
		ID   string `json:"id"`
		Body string `json:"body"`
	} `json:"operations"`
}

// Load reads and parses an Apollo persisted-query manifest into a hash→document
// map. A blank path returns an empty map (callers decide whether that is fatal).
func Load(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read persisted-operations manifest: %w", err)
	}
	var manifest apolloManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse persisted-operations manifest: %w", err)
	}
	docs := make(map[string]string, len(manifest.Operations))
	for _, op := range manifest.Operations {
		if op.ID == "" || op.Body == "" {
			continue
		}
		docs[op.ID] = op.Body
	}
	return docs, nil
}
