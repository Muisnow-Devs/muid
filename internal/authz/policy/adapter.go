package policy

import (
	"context"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"

	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/casbinrule"
	"sanzi.io/muid/pkg/enttx"
)

// EntAdapter persists casbin rules in the authz casbin_rule table. It
// implements persist.Adapter and persist.BatchAdapter.
//
// The Manager keeps auto-save disabled and writes rules itself inside the
// same transaction as the relational rows, so at runtime only LoadPolicy is
// exercised; the write methods exist for completeness (raw-policy admin
// paths and tests).
//
// casbin's adapter interfaces carry no context, so all methods run on
// context.Background.
type EntAdapter struct {
	db *authzent.Client
}

var (
	_ persist.Adapter      = (*EntAdapter)(nil)
	_ persist.BatchAdapter = (*EntAdapter)(nil)
)

// NewEntAdapter returns an adapter over the given ent client.
func NewEntAdapter(db *authzent.Client) *EntAdapter {
	return &EntAdapter{db: db}
}

// LoadPolicy loads all policy rules from casbin_rule.
func (a *EntAdapter) LoadPolicy(m model.Model) error {
	ctx := context.Background()
	rows, err := a.db.CasbinRule.Query().
		Order(casbinrule.ByCreatedAt(), casbinrule.ByID()).
		All(ctx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		err = persist.LoadPolicyArray(ruleFromRow(row).line(), m)
		if err != nil {
			return err
		}
	}
	return nil
}

// SavePolicy replaces the whole casbin_rule table with the model's rules.
func (a *EntAdapter) SavePolicy(m model.Model) error {
	var rules []Rule
	for _, sec := range []string{"p", "g"} {
		for ptype, ast := range m[sec] {
			for _, values := range ast.Policy {
				rules = append(rules, Rule{Ptype: ptype, Values: trimValues(values)})
			}
		}
	}

	return enttx.Do(context.Background(), a.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) error {
			_, err := tx.CasbinRule.Delete().Exec(ctx)
			if err != nil {
				return err
			}
			return insertRules(ctx, tx.CasbinRule, rules)
		})
}

// AddPolicy adds one rule.
func (a *EntAdapter) AddPolicy(_ string, ptype string, rule []string) error {
	r := Rule{Ptype: ptype, Values: trimValues(rule)}
	_, err := ruleCreate(a.db.CasbinRule.Create(), r).Save(context.Background())
	return err
}

// AddPolicies adds rules atomically.
func (a *EntAdapter) AddPolicies(_ string, ptype string, rules [][]string) error {
	batch := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		batch = append(batch, Rule{Ptype: ptype, Values: trimValues(rule)})
	}
	return enttx.Do(context.Background(), a.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) error {
			return insertRules(ctx, tx.CasbinRule, batch)
		})
}

// RemovePolicy removes one rule.
func (a *EntAdapter) RemovePolicy(_ string, ptype string, rule []string) error {
	r := Rule{Ptype: ptype, Values: trimValues(rule)}
	_, err := deleteRule(context.Background(), a.db.CasbinRule, r)
	return err
}

// RemovePolicies removes rules atomically.
func (a *EntAdapter) RemovePolicies(_ string, ptype string, rules [][]string) error {
	return enttx.Do(context.Background(), a.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) error {
			for _, rule := range rules {
				r := Rule{Ptype: ptype, Values: trimValues(rule)}
				_, err := deleteRule(ctx, tx.CasbinRule, r)
				if err != nil {
					return err
				}
			}
			return nil
		})
}

// RemoveFilteredPolicy removes rules of ptype whose columns starting at
// fieldIndex match the given values (empty values match anything).
func (a *EntAdapter) RemoveFilteredPolicy(
	_ string,
	ptype string,
	fieldIndex int,
	fieldValues ...string,
) error {
	if fieldIndex < 0 || fieldIndex+len(fieldValues) > ruleColumns {
		return ErrInvalidRule
	}

	del := a.db.CasbinRule.Delete().Where(casbinrule.Ptype(ptype))
	for i, value := range fieldValues {
		if value == "" {
			continue
		}
		switch fieldIndex + i {
		case 0:
			del = del.Where(casbinrule.V0(value))
		case 1:
			del = del.Where(casbinrule.V1(value))
		case 2:
			del = del.Where(casbinrule.V2(value))
		case 3:
			del = del.Where(casbinrule.V3(value))
		case 4:
			del = del.Where(casbinrule.V4(value))
		case 5:
			del = del.Where(casbinrule.V5(value))
		}
	}

	_, err := del.Exec(context.Background())
	return err
}
