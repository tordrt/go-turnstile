// Package turnstile provides a simple, thread-safe client for verifying Cloudflare Turnstile CAPTCHA tokens.
//
// Cloudflare Turnstile is a privacy-preserving alternative to traditional CAPTCHAs that helps websites
// protect against bots and automated traffic while providing a better user experience.
//
// Basic Usage:
//
//	client, err := turnstile.New("your-site-key", "your-secret-key")
//	if err != nil {
//		// Handle client creation error
//	}
//
//	// Verify token from HTTP request
//	response, err := client.VerifyRequest(context.Background(), httpRequest)
//	if err != nil {
//		// Handle verification error (specific error types available)
//		var timeoutErr turnstile.ErrTimeoutOrDuplicate
//		if errors.As(err, &timeoutErr) {
//			// Handle timeout/duplicate specifically
//		}
//		return
//	}
//	// Token is valid, access response fields: response.ChallengeTS, response.Hostname, response.Action, etc.
//
// Direct Token Verification:
//
//	client, _ := turnstile.New("your-site-key", "your-secret-key")
//	response, err := client.VerifyToken(context.Background(), tokenFromForm, "192.168.1.1")
//	if err != nil {
//		// Handle verification error
//		return
//	}
//	// Token is valid, proceed with business logic
//
// Advanced Configuration:
//
//	client, err := turnstile.New(
//		"your-site-key",
//		"your-secret-key",
//		turnstile.WithMaxRetries(3),
//		turnstile.WithRetryDelay(200*time.Millisecond),
//		turnstile.WithHTTPClient(&http.Client{Timeout: 5*time.Second}),
//	)
package turnstile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	// DefaultVerifyEndpoint is the official Cloudflare Turnstile verification endpoint
	DefaultVerifyEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	// DefaultTimeout is the default HTTP client timeout for verification requests
	DefaultTimeout = 3 * time.Second
	// DefaultMaxRetries is the default maximum number of retry attempts for network failures
	DefaultMaxRetries = 2
	// DefaultRetryDelay is the default initial delay between retry attempts (exponential backoff)
	DefaultRetryDelay = 100 * time.Millisecond
)

// Client provides thread-safe verification of Cloudflare Turnstile tokens.
// All methods are safe for concurrent use by multiple goroutines.
// The client includes automatic retry logic for transient network failures
// and supports customizable timeouts, endpoints, and HTTP clients.
type Client struct {
	// SiteKey is the public site key from your Cloudflare Turnstile configuration.
	// This field is exported for read-only access and debugging purposes.
	SiteKey string

	// secretKey is the private secret key from your Cloudflare Turnstile configuration
	secretKey string

	// client is the HTTP client used for verification requests
	client *http.Client

	// verifyURL is the Cloudflare endpoint for token verification
	verifyURL string

	// maxRetries is the maximum number of retry attempts for network failures
	maxRetries int

	// retryDelay is the initial delay between retry attempts (uses exponential backoff)
	retryDelay time.Duration
}

// ClientOption is a function type used to configure a Client during creation.
// Options allow customization of HTTP client, endpoints, retry behavior, and other settings.
type ClientOption func(*Client)

// WithHTTPClient configures the client to use a custom HTTP client.
// This is useful for setting custom timeouts, transport configurations,
// or proxy settings.
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.client = client
	}
}

// WithVerifyEndpoint configures the client to use a custom verification endpoint.
// This is typically only needed for testing or enterprise deployments.
func WithVerifyEndpoint(endpoint string) ClientOption {
	return func(c *Client) {
		c.verifyURL = endpoint
	}
}

// WithMaxRetries configures the maximum number of retry attempts for transient network failures.
// Retries are only performed for network-level errors (timeouts, connection issues), not
// for Turnstile validation failures. Default is 2 retries.
func WithMaxRetries(maxRetries int) ClientOption {
	return func(c *Client) {
		c.maxRetries = maxRetries
	}
}

// WithRetryDelay configures the initial delay between retry attempts.
// The delay is doubled after each retry (exponential backoff). Default is 100ms.
func WithRetryDelay(delay time.Duration) ClientOption {
	return func(c *Client) {
		c.retryDelay = delay
	}
}

// New creates a new Turnstile client with the provided site key and secret key.
// The client is safe for concurrent use by multiple goroutines.
//
// Parameters:
//   - siteKey: The public site key from your Cloudflare Turnstile configuration
//   - secretKey: The secret key from your Cloudflare Turnstile configuration
//   - opts: Optional configuration functions to customize client behavior
//
// Returns an error if either key is empty or contains only whitespace.
func New(siteKey, secretKey string, opts ...ClientOption) (*Client, error) {
	if strings.TrimSpace(siteKey) == "" {
		return nil, ErrInvalidSiteKey
	}
	if strings.TrimSpace(secretKey) == "" {
		return nil, ErrInvalidSecretKey
	}

	c := &Client{
		SiteKey:   siteKey,
		secretKey: secretKey,
		client: &http.Client{
			Timeout: DefaultTimeout,
		},
		verifyURL:  DefaultVerifyEndpoint,
		maxRetries: DefaultMaxRetries,
		retryDelay: DefaultRetryDelay,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Response represents the complete response from the Cloudflare Turnstile verification API.
// It contains both success/failure information and additional metadata about the verification.
type Response struct {
	// Success indicates whether the token verification succeeded
	Success bool `json:"success"`
	// ChallengeTS is the timestamp of when the challenge was completed (ISO 8601 format)
	ChallengeTS string `json:"challenge_ts,omitempty"`
	// Hostname is the hostname of the site where the challenge was completed
	Hostname string `json:"hostname,omitempty"`
	// ErrorCodes contains specific error codes when Success is false
	ErrorCodes []string `json:"error-codes,omitempty"`
	// Action is the action name for this widget (configured in Cloudflare dashboard)
	Action string `json:"action,omitempty"`
	// CData is the customer data passed to the widget
	CData string `json:"cdata,omitempty"`
	// Metadata contains additional response metadata (Enterprise only)
	Metadata *ResponseMetadata `json:"metadata,omitempty"`
}

// ResponseMetadata contains additional verification metadata.
// These fields are only populated for Cloudflare Enterprise customers.
type ResponseMetadata struct {
	// EphemeralID is a unique identifier for this verification (Enterprise only)
	EphemeralID string `json:"ephemeral_id,omitempty"`
}

// VerificationError represents a verification failure returned by the Cloudflare API.
// It includes both a human-readable message and structured error codes for programmatic handling.
type VerificationError struct {
	// Message is a human-readable description of the verification failure
	Message string `json:"message"`
	// ErrorCodes contains the specific Cloudflare error codes for this failure
	ErrorCodes []string `json:"error_codes,omitempty"`
}

func (e *VerificationError) Error() string {
	if len(e.ErrorCodes) > 0 {
		return fmt.Sprintf("%s: %v", e.Message, e.ErrorCodes)
	}
	return e.Message
}

// Specific error types that correspond to each Cloudflare Turnstile error code.
// These types allow for precise error handling using errors.As() or type assertions.
// Each type embeds VerificationError to provide access to the underlying error details.
type (
	ErrMissingInputSecret   struct{ *VerificationError }
	ErrInvalidInputSecret   struct{ *VerificationError }
	ErrMissingInputResponse struct{ *VerificationError }
	ErrInvalidInputResponse struct{ *VerificationError }
	ErrBadRequest           struct{ *VerificationError }
	ErrTimeoutOrDuplicate   struct{ *VerificationError }
	ErrInternalError        struct{ *VerificationError }
)

// createSpecificError creates a typed error instance based on Cloudflare's error codes.
// This allows callers to use errors.As() for precise error handling instead of
// parsing error messages.
func createSpecificError(errorCodes []string) error {
	if len(errorCodes) == 0 {
		return &VerificationError{Message: "turnstile verification failed"}
	}

	baseErr := &VerificationError{
		Message:    "turnstile verification failed",
		ErrorCodes: errorCodes,
	}

	// Return specific error type based on first error code
	switch errorCodes[0] {
	case "missing-input-secret":
		return &ErrMissingInputSecret{baseErr}
	case "invalid-input-secret":
		return &ErrInvalidInputSecret{baseErr}
	case "missing-input-response":
		return &ErrMissingInputResponse{baseErr}
	case "invalid-input-response":
		return &ErrInvalidInputResponse{baseErr}
	case "bad-request":
		return &ErrBadRequest{baseErr}
	case "timeout-or-duplicate":
		return &ErrTimeoutOrDuplicate{baseErr}
	case "internal-error":
		return &ErrInternalError{baseErr}
	default:
		return baseErr
	}
}

// Package-level errors for client configuration and validation.
var (
	ErrInvalidSiteKey   = errors.New("site key cannot be empty")
	ErrInvalidSecretKey = errors.New("secret key cannot be empty")
	ErrEmptyToken       = &VerificationError{Message: "turnstile response token cannot be empty"}
)

// isRetryableError determines whether a given error represents a transient network condition
// that should be retried. Only network-level errors are considered retryable; Turnstile
// validation failures are not retried as they indicate legitimate verification problems.
func isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsTemporary {
		return true
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return opErr.Temporary()
	}

	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "network is unreachable") ||
		strings.Contains(errStr, "connection timeout")
}

// VerifyRequest extracts and verifies a Turnstile token from an HTTP request.
//
// The method automatically:
//   - Extracts the token from the "cf-turnstile-response" form field
//   - Determines the client IP from the request's RemoteAddr
//   - Generates a unique idempotency key to prevent replay attacks
//
// This is the recommended method for most web applications as it handles
// the common case of form-based token submission.
//
// Returns the Cloudflare response on success, or a specific error type on failure.
func (c *Client) VerifyRequest(ctx context.Context, req *http.Request) (*Response, error) {
	token := req.FormValue("cf-turnstile-response")

	// Extract IP from RemoteAddr (format is "IP:port")
	remoteIP := req.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	return c.VerifyToken(ctx, token, remoteIP)
}

// VerifyToken directly verifies a Turnstile token with optional remote IP validation.
//
// Parameters:
//   - ctx: Context for request cancellation and timeout control
//   - token: The Turnstile response token to verify
//   - remoteIP: Optional client IP address for additional validation
//
// The method automatically generates a unique idempotency key to prevent replay attacks.
// If network errors occur, the request will be retried according to the client's
// retry configuration.
//
// Returns the Cloudflare response on success, or a specific error type on failure.
// Check the error type using errors.As() for detailed error handling.
func (c *Client) VerifyToken(ctx context.Context, token string, remoteIP ...string) (*Response, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrEmptyToken
	}

	var lastErr error
	delay := c.retryDelay

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("context cancelled during retry: %w", ctx.Err())
			case <-time.After(delay):
			}
			delay *= 2
		}

		response, err := c.doVerifyRequest(ctx, token, remoteIP...)
		if err != nil {
			lastErr = err
			if attempt < c.maxRetries && isRetryableError(err) {
				continue
			}
			return nil, err
		}

		return response, nil
	}

	return nil, lastErr
}

// doVerifyRequest performs the actual HTTP verification request to Cloudflare.
// This method handles the low-level details of constructing the multipart form request
// and parsing the JSON response. It does not perform retries - that logic is handled
// by the calling VerifyToken method.
func (c *Client) doVerifyRequest(ctx context.Context, token string, remoteIP ...string) (*Response, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if err := writer.WriteField("secret", c.secretKey); err != nil {
		return nil, fmt.Errorf("failed to write secret field: %w", err)
	}
	if err := writer.WriteField("response", token); err != nil {
		return nil, fmt.Errorf("failed to write response field: %w", err)
	}
	if len(remoteIP) > 0 && strings.TrimSpace(remoteIP[0]) != "" {
		if err := writer.WriteField("remoteip", remoteIP[0]); err != nil {
			return nil, fmt.Errorf("failed to write remoteip field: %w", err)
		}
	}
	if err := writer.WriteField("idempotency_key", uuid.New().String()); err != nil {
		return nil, fmt.Errorf("failed to write idempotency_key field: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.verifyURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	result, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = result.Body.Close()
	}()

	// Check HTTP status code before attempting to decode JSON
	if result.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status: %d %s", result.StatusCode, result.Status)
	}

	var response Response
	if err := json.NewDecoder(result.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return &response, createSpecificError(response.ErrorCodes)
	}

	return &response, nil
}
