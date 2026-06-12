package policy

import (
	"context"
	"errors"

	"github.com/google/uuid"

	authzevent "sanzi.io/muid/api/proto/event/v1/authz"
	authzent "sanzi.io/muid/internal/authz/ent"
	"sanzi.io/muid/internal/authz/ent/casbinrule"
	"sanzi.io/muid/internal/authz/ent/organizationmember"
	"sanzi.io/muid/internal/authz/ent/organizationrole"
	"sanzi.io/muid/internal/authz/ent/userref"
	"sanzi.io/muid/pkg/enttx"
	"sanzi.io/muid/pkg/shared/authzmodel"
)

// AddMember adds a user to an organization with the given role. actorID is
// the caller for the owner-grant guard; uuid.Nil (platform/admin paths)
// skips the guard.
func (m *Manager) AddMember(
	ctx context.Context,
	actorID, organizationID, userID uuid.UUID,
	roleName string,
) error {
	err := m.requireOrganization(ctx, organizationID)
	if err != nil {
		return err
	}
	role, err := m.roleByName(ctx, organizationID, roleName)
	if err != nil {
		return err
	}
	err = m.guardOwnerGrant(ctx, actorID, organizationID, roleName)
	if err != nil {
		return err
	}

	domain := organizationID.String()
	grouping := membershipRule(userID, roleName, domain)

	rev, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (uuid.UUID, error) {
			err := ensureUserRef(ctx, tx, userID)
			if err != nil {
				return uuid.Nil, err
			}
			_, err = tx.OrganizationMember.Create().
				SetOrganizationID(organizationID).
				SetUserID(userID).
				SetRoleID(role.ID).
				Save(ctx)
			if authzent.IsConstraintError(err) {
				return uuid.Nil, ErrAlreadyMember
			}
			if err != nil {
				return uuid.Nil, err
			}
			err = insertRules(ctx, tx.CasbinRule, []Rule{grouping})
			if err != nil {
				return uuid.Nil, err
			}
			return bumpRevision(ctx, tx)
		})
	if err != nil {
		return err
	}

	m.memoryAddRules(ctx, []Rule{grouping})
	m.publishChange(ctx, policyChange{
		kind:     authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_MEMBERSHIP_CHANGED,
		orgID:    organizationID,
		role:     roleName,
		userID:   userID,
		revision: rev,
	})
	return nil
}

// RemoveMember removes a user from an organization. Removing an owner
// requires the actor to be an owner (unless actorID is uuid.Nil) and never
// removes the last owner.
func (m *Manager) RemoveMember(
	ctx context.Context,
	actorID, organizationID, userID uuid.UUID,
) error {
	member, currentRole, err := m.memberWithRole(ctx, organizationID, userID)
	if err != nil {
		return err
	}
	if currentRole == RoleOwner {
		err = m.guardOwnerGrant(ctx, actorID, organizationID, RoleOwner)
		if err != nil {
			return err
		}
		err = m.guardLastOwner(ctx, organizationID)
		if err != nil {
			return err
		}
	}

	domain := organizationID.String()
	subject := authzmodel.UserSubject(userID)

	rev, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (uuid.UUID, error) {
			err := tx.OrganizationMember.DeleteOneID(member.ID).Exec(ctx)
			if err != nil {
				return uuid.Nil, err
			}
			_, err = tx.CasbinRule.Delete().
				Where(
					casbinrule.Ptype("g"),
					casbinrule.V0(subject),
					casbinrule.V2(domain),
				).
				Exec(ctx)
			if err != nil {
				return uuid.Nil, err
			}
			return bumpRevision(ctx, tx)
		})
	if err != nil {
		return err
	}

	m.memoryRemoveRules(ctx, []Rule{membershipRule(userID, currentRole, domain)})
	m.publishChange(ctx, policyChange{
		kind:     authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_MEMBERSHIP_CHANGED,
		orgID:    organizationID,
		userID:   userID,
		revision: rev,
	})
	return nil
}

// ChangeMemberRole reassigns a member to another role with the owner guard
// rails (last-owner protection; only owners grant or revoke owner).
func (m *Manager) ChangeMemberRole(
	ctx context.Context,
	actorID, organizationID, userID uuid.UUID,
	roleName string,
) error {
	member, currentRole, err := m.memberWithRole(ctx, organizationID, userID)
	if err != nil {
		return err
	}
	if currentRole == roleName {
		return nil
	}
	newRole, err := m.roleByName(ctx, organizationID, roleName)
	if err != nil {
		return err
	}
	if currentRole == RoleOwner || roleName == RoleOwner {
		err = m.guardOwnerGrant(ctx, actorID, organizationID, RoleOwner)
		if err != nil {
			return err
		}
	}
	if currentRole == RoleOwner {
		err = m.guardLastOwner(ctx, organizationID)
		if err != nil {
			return err
		}
	}

	domain := organizationID.String()
	oldRule := membershipRule(userID, currentRole, domain)
	newRule := membershipRule(userID, roleName, domain)

	rev, err := enttx.Run(ctx, m.db.Tx,
		func(ctx context.Context, tx *authzent.Tx) (uuid.UUID, error) {
			err := tx.OrganizationMember.UpdateOneID(member.ID).
				SetRoleID(newRole.ID).
				Exec(ctx)
			if err != nil {
				return uuid.Nil, err
			}
			_, err = deleteRule(ctx, tx.CasbinRule, oldRule)
			if err != nil {
				return uuid.Nil, err
			}
			err = insertRules(ctx, tx.CasbinRule, []Rule{newRule})
			if err != nil {
				return uuid.Nil, err
			}
			return bumpRevision(ctx, tx)
		})
	if err != nil {
		return err
	}

	m.memoryRemoveRules(ctx, []Rule{oldRule})
	m.memoryAddRules(ctx, []Rule{newRule})
	m.publishChange(ctx, policyChange{
		kind:     authzevent.PolicyChangeKind_POLICY_CHANGE_KIND_MEMBERSHIP_CHANGED,
		orgID:    organizationID,
		role:     roleName,
		userID:   userID,
		revision: rev,
	})
	return nil
}

// SetMember is the platform override (internal admin surface): add the user
// or change their role, skipping the owner-actor guard but keeping the
// last-owner protection.
func (m *Manager) SetMember(
	ctx context.Context,
	organizationID, userID uuid.UUID,
	roleName string,
) error {
	isMember, err := m.IsMember(ctx, organizationID, userID)
	if err != nil {
		return err
	}
	if isMember {
		return m.ChangeMemberRole(ctx, uuid.Nil, organizationID, userID, roleName)
	}
	return m.AddMember(ctx, uuid.Nil, organizationID, userID, roleName)
}

// memberWithRole loads a member row plus role name, mapping not-found to
// ErrNotMember.
func (m *Manager) memberWithRole(
	ctx context.Context,
	organizationID, userID uuid.UUID,
) (*authzent.OrganizationMember, string, error) {
	member, err := m.db.OrganizationMember.Query().
		Where(
			organizationmember.OrganizationID(organizationID),
			organizationmember.UserID(userID),
		).
		WithRole().
		Only(ctx)
	if authzent.IsNotFound(err) {
		return nil, "", ErrNotMember
	}
	if err != nil {
		return nil, "", err
	}
	roleName := ""
	if member.Edges.Role != nil {
		roleName = member.Edges.Role.Name
	}
	return member, roleName, nil
}

// guardOwnerGrant requires the actor to be an owner when granting or
// revoking the owner role. uuid.Nil actors (internal admin surface) skip
// the guard.
func (m *Manager) guardOwnerGrant(
	ctx context.Context,
	actorID, organizationID uuid.UUID,
	roleName string,
) error {
	if roleName != RoleOwner || actorID == uuid.Nil {
		return nil
	}
	_, actorRole, err := m.memberWithRole(ctx, organizationID, actorID)
	if err != nil && !errors.Is(err, ErrNotMember) {
		return err
	}
	if actorRole != RoleOwner {
		return ErrPermissionDenied
	}
	return nil
}

// guardLastOwner rejects mutations that would leave the organization
// without an owner.
func (m *Manager) guardLastOwner(ctx context.Context, organizationID uuid.UUID) error {
	owners, err := m.db.OrganizationMember.Query().
		Where(
			organizationmember.OrganizationID(organizationID),
			organizationmember.HasRoleWith(organizationrole.Name(RoleOwner)),
		).
		Count(ctx)
	if err != nil {
		return err
	}
	if owners <= 1 {
		return ErrLastOwner
	}
	return nil
}

// ensureUserRef creates the UserRef row backing the membership FK when it
// does not exist yet.
func ensureUserRef(ctx context.Context, tx *authzent.Tx, userID uuid.UUID) error {
	exists, err := tx.UserRef.Query().Where(userref.ID(userID)).Exist(ctx)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err = tx.UserRef.Create().SetID(userID).Save(ctx)
	return err
}

// membershipRule is the g-rule mirroring one membership row.
func membershipRule(userID uuid.UUID, roleName, domain string) Rule {
	return Rule{
		Ptype: "g",
		Values: []string{
			authzmodel.UserSubject(userID),
			authzmodel.RoleSubject(roleName),
			domain,
		},
	}
}
