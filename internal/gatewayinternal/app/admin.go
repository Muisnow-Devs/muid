package app

import (
	"context"
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	authnpb "sanzi.io/muid/api/proto/authn/v1"
	authzpb "sanzi.io/muid/api/proto/authz/v1"
	"sanzi.io/muid/pkg/gateway/httpmeta"
	"sanzi.io/muid/pkg/gateway/httpx"
	"sanzi.io/muid/pkg/gateway/jwtauth"
	"sanzi.io/muid/pkg/log"
)

// adminHandlers proxy a representative slice of the internal admin gRPC surface
// to HTTP. Responses are serialized verbatim with protojson; caller identity is
// forwarded as x-user-id so the backends enforce permissions.
type adminHandlers struct {
	oidc  authnpb.OIDCClientAdminServiceClient
	authz authzpb.AuthzAdminServiceClient
}

func newAdminHandlers(deps *InfraDependencies) *adminHandlers {
	return &adminHandlers{oidc: deps.OIDCAdmin, authz: deps.AuthzAdmin}
}

// outgoing attaches the verified admin's user id to the outbound gRPC metadata.
func outgoing(ctx context.Context) context.Context {
	if claims, ok := jwtauth.ClaimsFromContext(ctx); ok {
		return httpmeta.WithOutgoing(ctx, httpmeta.Fields{UserID: claims.UserID.String()})
	}
	return ctx
}

// listCasbinRules GET /admin/authz/casbin-rules?domain=&ptype=
func (h *adminHandlers) listCasbinRules(w http.ResponseWriter, r *http.Request) {
	req := &authzpb.ListCasbinRulesRequest{}
	req.SetDomain(r.URL.Query().Get("domain"))
	req.SetPtype(r.URL.Query().Get("ptype"))

	resp, err := h.authz.ListCasbinRules(outgoing(r.Context()), req)
	if err != nil {
		writeUpstreamError(w, r, err)
		return
	}
	writeProto(w, r, resp)
}

// reloadPolicy POST /admin/authz/reload-policy
func (h *adminHandlers) reloadPolicy(w http.ResponseWriter, r *http.Request) {
	resp, err := h.authz.ReloadPolicyConfig(outgoing(r.Context()), &authzpb.ReloadPolicyConfigRequest{})
	if err != nil {
		writeUpstreamError(w, r, err)
		return
	}
	writeProto(w, r, resp)
}

// listOIDCClients GET /admin/oidc/clients?organization_id=
func (h *adminHandlers) listOIDCClients(w http.ResponseWriter, r *http.Request) {
	req := &authnpb.ListOIDCClientsRequest{}
	req.SetOrganizationId(r.URL.Query().Get("organization_id"))

	resp, err := h.oidc.ListOIDCClients(outgoing(r.Context()), req)
	if err != nil {
		writeUpstreamError(w, r, err)
		return
	}
	writeProto(w, r, resp)
}

// writeProto serializes a proto message to JSON via protojson.
func writeProto(w http.ResponseWriter, r *http.Request, msg proto.Message) {
	data, err := protojson.Marshal(msg)
	if err != nil {
		log.LogUnexpected(r.Context(), "gateway-internal protojson marshal", err.Error())
		httpx.Error(w, http.StatusInternalServerError, "internal_error", "failed to encode response")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

// writeUpstreamError maps a gRPC status to an HTTP status without leaking the
// raw error message to the client.
func writeUpstreamError(w http.ResponseWriter, r *http.Request, err error) {
	st, ok := status.FromError(err)
	if !ok {
		log.LogUnexpected(r.Context(), "gateway-internal upstream call", err.Error())
		httpx.Error(w, http.StatusBadGateway, "upstream_error", "upstream service error")
		return
	}
	switch st.Code() {
	case codes.InvalidArgument:
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "invalid request")
	case codes.Unauthenticated:
		httpx.Error(w, http.StatusUnauthorized, "unauthorized", "unauthorized")
	case codes.PermissionDenied:
		httpx.Error(w, http.StatusForbidden, "forbidden", "permission denied")
	case codes.NotFound:
		httpx.Error(w, http.StatusNotFound, "not_found", "not found")
	default:
		log.LogUnexpected(r.Context(), "gateway-internal upstream call", err.Error())
		httpx.Error(w, http.StatusBadGateway, "upstream_error", "upstream service error")
	}
}
