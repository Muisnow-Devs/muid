package authzclient

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/pkg/log"
	"sanzi.io/muid/pkg/shared/authzmodel"
	"sanzi.io/muid/pkg/shared/kv"
)

// cachedRoles is the KV payload for one (user, org) role resolution.
type cachedRoles struct {
	Roles    []string `json:"roles"`
	IsMember bool     `json:"is_member"`
}

// roleCacheKey builds both the process-local map key and the KV key suffix.
func (e *Enforcer) roleCacheKey(userID, organizationID uuid.UUID) string {
	return organizationID.String() + ":" + userID.String()
}

func (e *Enforcer) kvKey(localKey string) string {
	return "authz:roles:" + e.cfg.Namespace + ":" + localKey
}

// entryGroupings expands a cache entry back to its injected g-rules. The
// key is "<org>:<user>".
func entryGroupings(key string, entry roleEntry) [][]string {
	org, user, ok := strings.Cut(key, ":")
	if !ok {
		return nil
	}
	rules := make([][]string, 0, len(entry.roles))
	for _, role := range entry.roles {
		rules = append(rules, []string{
			authzmodel.UserSubjectPrefix + user,
			authzmodel.RoleSubject(role),
			org,
		})
	}
	return rules
}

// ensureRoles returns the cached role resolution for (user, org), fetching
// through KV and then the authz RPC on miss, and injecting the user's
// g-rules into the local model. Negative results (non-members) are cached
// too.
func (e *Enforcer) ensureRoles(
	ctx context.Context,
	userID, organizationID uuid.UUID,
) (roleEntry, error) {
	key := e.roleCacheKey(userID, organizationID)

	e.mu.Lock()
	if !e.started {
		e.mu.Unlock()
		return roleEntry{}, ErrNotStarted
	}
	entry, ok := e.roleCache[key]
	e.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry, nil
	}

	resolved, err := e.lookupRoles(ctx, key, userID, organizationID)
	if err != nil {
		return roleEntry{}, err
	}

	entry = roleEntry{
		roles:    resolved.Roles,
		isMember: resolved.IsMember,
		expires:  time.Now().Add(e.cfg.RoleCacheTTL),
	}
	e.mu.Lock()
	// Replace any stale groupings before injecting the fresh ones.
	if old, ok := e.roleCache[key]; ok {
		e.removeGroupingsLocked(ctx, key, old)
	}
	e.roleCache[key] = entry
	for _, g := range entryGroupings(key, entry) {
		_, err = e.enf.AddGroupingPolicy(toAny(g)...)
		if err != nil {
			e.mu.Unlock()
			return roleEntry{}, err
		}
	}
	e.mu.Unlock()
	return entry, nil
}

// lookupRoles checks KV then falls back to the authz RPC, writing the
// result back to KV.
func (e *Enforcer) lookupRoles(
	ctx context.Context,
	key string,
	userID, organizationID uuid.UUID,
) (cachedRoles, error) {
	if e.cfg.KV != nil {
		payload, err := e.cfg.KV.Get(ctx, e.kvKey(key))
		if err != nil && !errors.Is(err, kv.ErrKeyNotFound) {
			log.LogUnexpected(ctx, "authzclient role cache get", err.Error(), log.UserID(userID))
		}
		if err == nil {
			var cached cachedRoles
			err = json.Unmarshal(payload, &cached)
			if err == nil {
				return cached, nil
			}
			log.LogUnexpected(ctx, "authzclient role cache decode", err.Error(), log.UserID(userID))
		}
	}

	req := &authzpb.ListUserOrganizationRolesRequest{}
	req.SetUserId(userID.String())
	req.SetOrganizationId(organizationID.String())
	resp, err := e.cfg.Client.ListUserOrganizationRoles(ctx, req)
	if err != nil {
		return cachedRoles{}, err
	}
	resolved := cachedRoles{Roles: resp.GetRoles(), IsMember: resp.GetIsMember()}

	if e.cfg.KV != nil {
		payload, err := json.Marshal(resolved)
		if err == nil {
			err = e.cfg.KV.Set(ctx, e.kvKey(key), payload, e.cfg.RoleCacheTTL)
		}
		if err != nil {
			log.LogUnexpected(ctx, "authzclient role cache set", err.Error(), log.UserID(userID))
		}
	}
	return resolved, nil
}

// evictRoles drops the cached resolution and injected g-rules for one
// (user, org); the next check re-fetches.
func (e *Enforcer) evictRoles(ctx context.Context, userID, organizationID uuid.UUID) {
	key := e.roleCacheKey(userID, organizationID)

	if e.cfg.KV != nil {
		err := e.cfg.KV.Delete(ctx, e.kvKey(key))
		if err != nil && !errors.Is(err, kv.ErrKeyNotFound) {
			log.LogUnexpected(ctx, "authzclient role cache delete", err.Error(), log.UserID(userID))
		}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	entry, ok := e.roleCache[key]
	if !ok {
		return
	}
	e.removeGroupingsLocked(ctx, key, entry)
	delete(e.roleCache, key)
}

// evictOrganization drops every cached resolution for one organization.
func (e *Enforcer) evictOrganization(ctx context.Context, organizationID uuid.UUID) {
	prefix := organizationID.String() + ":"

	e.mu.Lock()
	defer e.mu.Unlock()
	for key, entry := range e.roleCache {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if e.cfg.KV != nil {
			err := e.cfg.KV.Delete(ctx, e.kvKey(key))
			if err != nil && !errors.Is(err, kv.ErrKeyNotFound) {
				log.LogUnexpected(ctx, "authzclient role cache delete", err.Error())
			}
		}
		e.removeGroupingsLocked(ctx, key, entry)
		delete(e.roleCache, key)
	}
}

// removeGroupingsLocked removes a cache entry's injected g-rules. Callers
// hold e.mu.
func (e *Enforcer) removeGroupingsLocked(ctx context.Context, key string, entry roleEntry) {
	for _, g := range entryGroupings(key, entry) {
		_, err := e.enf.RemoveGroupingPolicy(toAny(g)...)
		if err != nil {
			log.LogUnexpected(ctx, "authzclient grouping eviction", err.Error())
		}
	}
}

func toAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}
