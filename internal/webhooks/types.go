package webhooks

import (
	"errors"
	"time"
)

const (
	EventRunSucceeded      = "run.succeeded"
	EventRunFailed         = "run.failed"
	EventRunCancelled      = "run.cancelled"
	EventApprovalRequested = "approval.requested"

	DeliveryStatusPending   = "PENDING"
	DeliveryStatusDelivered = "DELIVERED"
	DeliveryStatusFailed    = "FAILED"
	DeliveryStatusCancelled = "CANCELLED"

	PayloadVersionV1 = 1

	MaxAttempts   = 12
	MaxDeliveryAge = 24 * time.Hour

	ConnectTimeout = 3 * time.Second
	TotalTimeout   = 10 * time.Second

	HeaderSignature = "X-Deadbolt-Signature"
	HeaderTimestamp = "X-Deadbolt-Timestamp"
	HeaderKeyID     = "X-Deadbolt-Key-ID"
	HeaderEvent     = "X-Deadbolt-Event"
	HeaderDelivery  = "X-Deadbolt-Delivery"

	SignatureTolerance = 5 * time.Minute
	RotationOverlap    = 24 * time.Hour
)

var (
	ErrEndpointNotFound = errors.New("webhook endpoint not found")
	ErrDeliveryNotFound = errors.New("webhook delivery not found")
	ErrRevisionConflict = errors.New("webhook endpoint revision conflict")
	ErrInvalidURL       = errors.New("invalid webhook URL")
	ErrSSRFBlocked      = errors.New("destination IP or address blocked by SSRF defense")
	ErrInvalidEvent     = errors.New("unsupported webhook event type")
	ErrInvalidSignatureHeader = errors.New("invalid signature header format")
)

// ValidEventTypes returns true if event is one of the supported V1 webhook events
func IsValidEventType(evt string) bool {
	switch evt {
	case EventRunSucceeded, EventRunFailed, EventRunCancelled, EventApprovalRequested:
		return true
	default:
		return false
	}
}

type WebhookEndpoint struct {
	ID                     string     `json:"id"`
	OrganizationID         string     `json:"organizationId"`
	EnvironmentID          string     `json:"environmentId"`
	URL                    string     `json:"url"`
	EncryptedSecret        string     `json:"-"`
	SigningKeyID           string     `json:"signingKeyId"`
	PreviousEncryptedSecret *string    `json:"-"`
	PreviousSigningKeyID   *string    `json:"previousSigningKeyId,omitempty"`
	RotatedAt              *time.Time `json:"rotatedAt,omitempty"`
	SubscribedEvents       []string   `json:"subscribedEvents"`
	Active                 bool       `json:"active"`
	Revision               int64      `json:"revision"`
	CreatedAt              time.Time  `json:"createdAt"`
	UpdatedAt              time.Time  `json:"updatedAt"`
}

type WebhookDelivery struct {
	ID               string     `json:"id"`
	OrganizationID   string     `json:"organizationId"`
	EndpointID       string     `json:"endpointId"`
	EndpointRevision int64      `json:"endpointRevision"`
	EventID          string     `json:"eventId"`
	EventType        string     `json:"eventType"`
	RunID            *string    `json:"runId,omitempty"`
	Payload          map[string]any `json:"payload"`
	Attempts         int        `json:"attempts"`
	Status           string     `json:"status"`
	NextAt           time.Time  `json:"nextAt"`
	DeliveredAt      *time.Time `json:"deliveredAt,omitempty"`
	LastStatusCode   *int       `json:"lastStatusCode,omitempty"`
	LastError        *string    `json:"lastError,omitempty"`
	ResponseSnippet  *string    `json:"responseSnippet,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	CompletedAt      *time.Time `json:"completedAt,omitempty"`
}

type EventPayload struct {
	ID             string         `json:"id"`
	EventType      string         `json:"eventType"`
	EnvironmentID  string         `json:"environmentId"`
	RunID          string         `json:"runId,omitempty"`
	PayloadVersion int            `json:"payloadVersion"`
	CommittedAt    string         `json:"committedAt"`
	Summary        map[string]any `json:"summary"`
}

type WebhookEndpointDTO struct {
	ID           string   `json:"id,omitempty"`
	URL          string   `json:"url"`
	Enabled      bool     `json:"enabled"`
	Revision     int64    `json:"revision,omitempty"`
	EventTypes   []string `json:"eventTypes"`
	Secret       string   `json:"secret,omitempty"`
	SigningKeyID string   `json:"signingKeyId,omitempty"`
}

type WebhookDeliveryDTO struct {
	ID               string         `json:"id"`
	EndpointID       string         `json:"endpointId"`
	EndpointRevision int64          `json:"endpointRevision"`
	EventID          string         `json:"eventId"`
	EventType        string         `json:"eventType"`
	RunID            *string        `json:"runId,omitempty"`
	Payload          map[string]any `json:"payload"`
	Attempts         int            `json:"attempts"`
	Status           string         `json:"status"`
	NextAt           string         `json:"nextAt"`
	DeliveredAt      *string        `json:"deliveredAt,omitempty"`
	LastStatusCode   *int           `json:"lastStatusCode,omitempty"`
	LastError        *string        `json:"lastError,omitempty"`
	ResponseSnippet  *string        `json:"responseSnippet,omitempty"`
	CreatedAt        string         `json:"createdAt"`
	CompletedAt      *string        `json:"completedAt,omitempty"`
}
