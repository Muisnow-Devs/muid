// Package policy is the authorization engine of the authz service: it owns
// the casbin enforcer, the casbin_rule table, the static-configuration
// reconciler, and every policy/role/membership mutation. All other authz
// code (gRPC handlers) goes through the Manager defined here.
package policy

import (
	"context"

	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/casbinrule"
)

// ruleColumns is the number of value columns (v0..v5) in casbin_rule.
const ruleColumns = 6

// Rule is one casbin rule: ptype ("p" or "g") plus values with trailing
// empty strings trimmed.
type Rule struct {
	Ptype  string
	Values []string
}

// line returns the rule in casbin text form ([ptype, v0, v1, ...]) as
// consumed by persist.LoadPolicyArray.
func (r Rule) line() []string {
	return append([]string{r.Ptype}, r.Values...)
}

// padded returns the rule values padded with empty strings to all six
// columns.
func (r Rule) padded() [ruleColumns]string {
	var out [ruleColumns]string
	copy(out[:], r.Values)
	return out
}

// trimValues drops trailing empty strings so equivalent rules compare equal
// regardless of how many columns the source filled.
func trimValues(values []string) []string {
	end := len(values)
	for end > 0 && values[end-1] == "" {
		end--
	}
	return values[:end]
}

// ruleFromRow converts a casbin_rule row back to a Rule.
func ruleFromRow(row *authzent.CasbinRule) Rule {
	values := []string{row.V0, row.V1, row.V2, row.V3, row.V4, row.V5}
	return Rule{Ptype: row.Ptype, Values: trimValues(values)}
}

// ruleCreate fills a create builder with the rule's columns.
func ruleCreate(create *authzent.CasbinRuleCreate, r Rule) *authzent.CasbinRuleCreate {
	v := r.padded()
	return create.
		SetPtype(r.Ptype).
		SetV0(v[0]).
		SetV1(v[1]).
		SetV2(v[2]).
		SetV3(v[3]).
		SetV4(v[4]).
		SetV5(v[5])
}

// insertRules bulk-inserts rules through any ent client (tx or root).
func insertRules(ctx context.Context, c *authzent.CasbinRuleClient, rules []Rule) error {
	if len(rules) == 0 {
		return nil
	}
	builders := make([]*authzent.CasbinRuleCreate, 0, len(rules))
	for _, r := range rules {
		builders = append(builders, ruleCreate(c.Create(), r))
	}
	_, err := c.CreateBulk(builders...).Save(ctx)
	return err
}

// deleteRule deletes the exact rule and reports whether a row was removed.
func deleteRule(ctx context.Context, c *authzent.CasbinRuleClient, r Rule) (bool, error) {
	v := r.padded()
	n, err := c.Delete().
		Where(
			casbinrule.Ptype(r.Ptype),
			casbinrule.V0(v[0]),
			casbinrule.V1(v[1]),
			casbinrule.V2(v[2]),
			casbinrule.V3(v[3]),
			casbinrule.V4(v[4]),
			casbinrule.V5(v[5]),
		).
		Exec(ctx)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
