package webhooks

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Ryanakml/Deadbolt/internal/tenant"
)

type HTTPHandler struct {
	service *Service
	tenants *tenant.Service
}

func NewHTTPHandler(s *Service, tenants *tenant.Service) *HTTPHandler {
	return &HTTPHandler{service: s, tenants: tenants}
}

type createEndpointRequest struct {
	URL        string   `json:"url"`
	Enabled    bool     `json:"enabled"`
	EventTypes []string `json:"eventTypes"`
}

type updateEndpointRequest struct {
	ExpectedRevision int64                  `json:"expectedRevision"`
	Configuration    *createEndpointRequest `json:"configuration"`
	RotateSecret     bool                   `json:"rotateSecret,omitempty"`
}

type deleteEndpointRequest struct {
	ExpectedRevision int64 `json:"expectedRevision"`
}

func (h *HTTPHandler) ListEndpoints(w http.ResponseWriter, r *http.Request) {
	caller, ok := tenant.CallerFromContext(r.Context())
	if !ok || caller == nil {
		errJSON(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}
	env, ok := h.resolveEnv(w, r, caller)
	if !ok {
		return
	}
	if !h.allowed(r, caller, env, tenant.CapWebhooksWrite) {
		errJSON(w, r, http.StatusForbidden, "FORBIDDEN", "Listing webhook endpoints is not permitted")
		return
	}

	limit := 25
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	cursor := r.URL.Query().Get("cursor")

	items, nextCursor, err := h.service.ListEndpoints(r.Context(), caller.OrganizationID, env, limit, cursor)
	if err != nil {
		writeServiceErr(w, r, err)
		return
	}

	dtos := make([]WebhookEndpointDTO, 0, len(items))
	for _, item := range items {
		dtos = append(dtos, toEndpointDTO(item, ""))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":      dtos,
		"nextCursor": nextCursor,
	})
}

func (h *HTTPHandler) CreateEndpoint(w http.ResponseWriter, r *http.Request) {
	caller, ok := tenant.CallerFromContext(r.Context())
	if !ok || caller == nil {
		errJSON(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}
	env, ok := h.resolveEnv(w, r, caller)
	if !ok {
		return
	}
	if !h.allowed(r, caller, env, tenant.CapWebhooksWrite) {
		errJSON(w, r, http.StatusForbidden, "FORBIDDEN", "Creating webhook endpoints is not permitted")
		return
	}

	var req createEndpointRequest
	if !decodeBody(w, r, &req) {
		return
	}

	endpoint, secret, err := h.service.CreateEndpoint(
		r.Context(), caller.OrganizationID, env, req.URL, req.EventTypes, auditFromCaller(caller, r),
	)
	if err != nil {
		writeServiceErr(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, toEndpointDTO(*endpoint, secret))
}

func (h *HTTPHandler) UpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	caller, ok := tenant.CallerFromContext(r.Context())
	if !ok || caller == nil {
		errJSON(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	endpointID := r.PathValue("id")
	if endpointID == "" {
		errJSON(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Endpoint ID is required")
		return
	}

	var req updateEndpointRequest
	if !decodeBody(w, r, &req) {
		return
	}

	// Fetch endpoint first to check environment authorization
	existing, err := h.service.GetEndpoint(r.Context(), caller.OrganizationID, endpointID)
	if err != nil {
		writeServiceErr(w, r, err)
		return
	}
	if !h.allowed(r, caller, existing.EnvironmentID, tenant.CapWebhooksWrite) {
		errJSON(w, r, http.StatusForbidden, "FORBIDDEN", "Updating webhook endpoint is not permitted")
		return
	}

	var newURL *string
	var enabled *bool
	var eventTypes []string

	if req.Configuration != nil {
		if req.Configuration.URL != "" {
			newURL = &req.Configuration.URL
		}
		enabled = &req.Configuration.Enabled
		eventTypes = req.Configuration.EventTypes
	}

	updated, newSecret, err := h.service.UpdateEndpoint(
		r.Context(), caller.OrganizationID, endpointID, req.ExpectedRevision,
		newURL, enabled, eventTypes, req.RotateSecret, auditFromCaller(caller, r),
	)
	if err != nil {
		writeServiceErr(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, toEndpointDTO(*updated, newSecret))
}

func (h *HTTPHandler) DeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	caller, ok := tenant.CallerFromContext(r.Context())
	if !ok || caller == nil {
		errJSON(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	endpointID := r.PathValue("id")
	if endpointID == "" {
		errJSON(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Endpoint ID is required")
		return
	}

	var req deleteEndpointRequest
	if !decodeBody(w, r, &req) {
		return
	}

	existing, err := h.service.GetEndpoint(r.Context(), caller.OrganizationID, endpointID)
	if err != nil {
		writeServiceErr(w, r, err)
		return
	}
	if !h.allowed(r, caller, existing.EnvironmentID, tenant.CapWebhooksWrite) {
		errJSON(w, r, http.StatusForbidden, "FORBIDDEN", "Deleting webhook endpoint is not permitted")
		return
	}

	if err := h.service.DeleteEndpoint(r.Context(), caller.OrganizationID, endpointID, req.ExpectedRevision, auditFromCaller(caller, r)); err != nil {
		writeServiceErr(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (h *HTTPHandler) ListDeliveries(w http.ResponseWriter, r *http.Request) {
	caller, ok := tenant.CallerFromContext(r.Context())
	if !ok || caller == nil {
		errJSON(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	endpointID := r.PathValue("id")
	if endpointID == "" {
		errJSON(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Endpoint ID is required")
		return
	}

	existing, err := h.service.GetEndpoint(r.Context(), caller.OrganizationID, endpointID)
	if err != nil {
		writeServiceErr(w, r, err)
		return
	}
	if !h.allowed(r, caller, existing.EnvironmentID, tenant.CapWebhooksWrite) {
		errJSON(w, r, http.StatusForbidden, "FORBIDDEN", "Listing webhook deliveries is not permitted")
		return
	}

	limit := 25
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	cursor := r.URL.Query().Get("cursor")

	deliveries, nextCursor, err := h.service.ListDeliveries(r.Context(), caller.OrganizationID, endpointID, limit, cursor)
	if err != nil {
		writeServiceErr(w, r, err)
		return
	}

	dtos := make([]WebhookDeliveryDTO, 0, len(deliveries))
	for _, d := range deliveries {
		dtos = append(dtos, toDeliveryDTO(d))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items":      dtos,
		"nextCursor": nextCursor,
	})
}

func (h *HTTPHandler) Redeliver(w http.ResponseWriter, r *http.Request) {
	caller, ok := tenant.CallerFromContext(r.Context())
	if !ok || caller == nil {
		errJSON(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "Authentication required")
		return
	}

	deliveryID := r.PathValue("id")
	if deliveryID == "" {
		errJSON(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Delivery ID is required")
		return
	}

	newDelivery, err := h.service.Redeliver(r.Context(), caller.OrganizationID, deliveryID, auditFromCaller(caller, r))
	if err != nil {
		writeServiceErr(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, toDeliveryDTO(*newDelivery))
}

func (h *HTTPHandler) resolveEnv(w http.ResponseWriter, r *http.Request, caller *tenant.CallerIdentity) (string, bool) {
	envParam := r.URL.Query().Get("environment")
	if envParam == "" {
		errJSON(w, r, http.StatusBadRequest, "MISSING_ENVIRONMENT", "Environment query parameter is required")
		return "", false
	}
	env := envParam
	if caller.Type == tenant.IdentityTypeMachine && (env == caller.EnvironmentName || env == caller.EnvironmentID) {
		env = caller.EnvironmentID
	} else if caller.Type != tenant.IdentityTypeMachine {
		environment, err := h.tenants.ResolveEnvironment(r.Context(), caller.OrganizationID, envParam)
		if err != nil {
			if errors.Is(err, tenant.ErrEnvironmentAmbiguous) {
				errJSON(w, r, http.StatusBadRequest, "AMBIGUOUS_ENVIRONMENT", "Environment name matches multiple environments; use the environment UUID")
				return "", false
			}
			errJSON(w, r, http.StatusNotFound, "NOT_FOUND", "Environment not found")
			return "", false
		}
		env = environment.ID
	}
	return env, true
}

func (h *HTTPHandler) allowed(r *http.Request, c *tenant.CallerIdentity, env, cap string) bool {
	if c.OrganizationID == "" {
		return false
	}
	if c.Type == tenant.IdentityTypeMachine {
		return c.EnvironmentID == env && tenant.CanAPIKeyPerform(c.Capabilities, cap)
	}
	m, err := h.tenants.GetMember(r.Context(), c.OrganizationID, c.UserID)
	return err == nil && m.Status == tenant.StatusActive && tenant.CanRolePerform(m.Role, cap)
}

func toEndpointDTO(ep WebhookEndpoint, secret string) WebhookEndpointDTO {
	dto := WebhookEndpointDTO{
		ID:           ep.ID,
		URL:          ep.URL,
		Enabled:      ep.Active,
		Revision:     ep.Revision,
		EventTypes:   ep.SubscribedEvents,
		SigningKeyID: ep.SigningKeyID,
	}
	if secret != "" {
		dto.Secret = secret
	}
	return dto
}

func toDeliveryDTO(d WebhookDelivery) WebhookDeliveryDTO {
	dto := WebhookDeliveryDTO{
		ID:               d.ID,
		EndpointID:       d.EndpointID,
		EndpointRevision: d.EndpointRevision,
		EventID:          d.EventID,
		EventType:        d.EventType,
		RunID:            d.RunID,
		Payload:          d.Payload,
		Attempts:         d.Attempts,
		Status:           d.Status,
		NextAt:           d.NextAt.UTC().Format(time.RFC3339Nano),
		CreatedAt:        d.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if d.DeliveredAt != nil {
		s := d.DeliveredAt.UTC().Format(time.RFC3339Nano)
		dto.DeliveredAt = &s
	}
	if d.CompletedAt != nil {
		s := d.CompletedAt.UTC().Format(time.RFC3339Nano)
		dto.CompletedAt = &s
	}
	dto.LastStatusCode = d.LastStatusCode
	dto.LastError = d.LastError
	dto.ResponseSnippet = d.ResponseSnippet
	return dto
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		errJSON(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func errJSON(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":      code,
		"message":   message,
		"requestId": tenant.RequestIDFromContext(r.Context()),
		"retryable": status >= 500,
	})
}

func writeServiceErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrEndpointNotFound):
		errJSON(w, r, http.StatusNotFound, "ENDPOINT_NOT_FOUND", "Webhook endpoint not found")
	case errors.Is(err, ErrDeliveryNotFound):
		errJSON(w, r, http.StatusNotFound, "DELIVERY_NOT_FOUND", "Webhook delivery not found")
	case errors.Is(err, ErrRevisionConflict):
		errJSON(w, r, http.StatusConflict, "REVISION_CONFLICT", "Webhook endpoint changed since it was read; refresh before acting")
	case errors.Is(err, ErrSSRFBlocked):
		errJSON(w, r, http.StatusUnprocessableEntity, "SSRF_DESTINATION_BLOCKED", err.Error())
	case errors.Is(err, ErrInvalidURL):
		errJSON(w, r, http.StatusUnprocessableEntity, "INVALID_URL", err.Error())
	case errors.Is(err, ErrInvalidEvent):
		errJSON(w, r, http.StatusUnprocessableEntity, "INVALID_EVENT_TYPE", err.Error())
	default:
		errJSON(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to process webhook request")
	}
}

func auditFromCaller(caller *tenant.CallerIdentity, r *http.Request) *tenant.AuditContext {
	if caller == nil {
		return nil
	}
	var id *string
	if caller.Type == tenant.IdentityTypeMachine {
		if caller.KeyID != "" {
			id = &caller.KeyID
		}
	} else if caller.UserID != "" {
		id = &caller.UserID
	}
	return &tenant.AuditContext{
		ActorID:       id,
		ActorType:     caller.Type,
		Role:          caller.Role,
		Capabilities:  caller.Capabilities,
		CorrelationID: tenant.RequestIDFromContext(r.Context()),
	}
}
