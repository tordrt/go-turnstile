// Package turnstile provides a simple client for verifying Cloudflare Turnstile CAPTCHA tokens.
//
// Turnstile is Cloudflare's smart CAPTCHA alternative that helps millions of websites
// welcoming, while keeping out bots and other unwanted traffic.
//
// Example usage:
//
//	client := turnstile.New("your-site-key", "your-secret-key")
//	_, err := client.VerifyRequest(context.Background(), httpRequest)
//	if err != nil {
//		// Handle error (specific error types available)
//		var timeoutErr *turnstile.ErrTimeoutOrDuplicate
//		if errors.As(err, &timeoutErr) {
//			// Handle timeout/duplicate specifically
//		}
//		return
//	}
//	// Token is valid, proceed
//	// Access the response fields if neccessery : response.ChallengeTS, response.Hostname, response.Action, etc.
//
// Or use VerifyToken directly with a token:
//
//	client := turnstile.New("your-site-key", "your-secret-key")
//	_, err := client.VerifyToken(context.Background(), tokenFromForm, "192.168.1.1")
//	if err != nil {
//		// Handle error
//		return
//	}
//	// Token is valid, proceed
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
	// DefaultVerifyEndpoint is the default Cloudflare Turnstile verification endpoint
	DefaultVerifyEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	// DefaultTimeout is the default HTTP timeout for verification requests
	DefaultTimeout = 3 * time.Second
	// DefaultMaxRetries is the default maximum number of retry attempts
	DefaultMaxRetries = 2
	// DefaultRetryDelay is the default initial delay between retries
	DefaultRetryDelay = 100 * time.Millisecond
)

// Client handles verification of Turnstile tokens.
// It is safe for concurrent use by multiple goroutines.
type Client struct {
	// SiteKey is the public site key from your Turnstile configuration
	SiteKey    string
	secretKey  string
	client     *http.Client
	verifyURL  string
	maxRetries int
	retryDelay time.Duration
}

// ClientOption configures a Client
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.client = client
	}
}

// WithVerifyEndpoint sets a custom verification endpoint
func WithVerifyEndpoint(endpoint string) ClientOption {
	return func(c *Client) {
		c.verifyURL = endpoint
	}
}

// WithMaxRetries sets the maximum number of retry attempts for network failures
func WithMaxRetries(maxRetries int) ClientOption {
	return func(c *Client) {
		c.maxRetries = maxRetries
	}
}

// WithRetryDelay sets the initial delay between retry attempts
func WithRetryDelay(delay time.Duration) ClientOption {
	return func(c *Client) {
		c.retryDelay = delay
	}
}

// New creates a new Turnstile client with the provided site key and secret key.
// Additional options can be provided to customize the client behavior.
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

// Response represents the Cloudflare Turnstile API response
type Response struct {
	Success     bool              `json:"success"`
	ChallengeTS string            `json:"challenge_ts,omitempty"`
	Hostname    string            `json:"hostname,omitempty"`
	ErrorCodes  []string          `json:"error-codes,omitempty"`
	Action      string            `json:"action,omitempty"`
	CData       string            `json:"cdata,omitempty"`
	Metadata    *ResponseMetadata `json:"metadata,omitempty"`
}

// ResponseMetadata contains additional response metadata (Enterprise only)
type ResponseMetadata struct {
	EphemeralID string `json:"ephemeral_id,omitempty"`
}

// VerificationError represents an error that occurred during token verification
type VerificationError struct {
	Message    string   `json:"message"`
	ErrorCodes []string `json:"error_codes,omitempty"`
}

func (e *VerificationError) Error() string {
	if len(e.ErrorCodes) > 0 {
		return fmt.Sprintf("%s: %v", e.Message, e.ErrorCodes)
	}
	return e.Message
}

// Specific error types for each Cloudflare error code
type (
	ErrMissingInputSecret   struct{ *VerificationError }
	ErrInvalidInputSecret   struct{ *VerificationError }
	ErrMissingInputResponse struct{ *VerificationError }
	ErrInvalidInputResponse struct{ *VerificationError }
	ErrBadRequest           struct{ *VerificationError }
	ErrTimeoutOrDuplicate   struct{ *VerificationError }
	ErrInternalError        struct{ *VerificationError }
)

// createSpecificError creates a specific error type based on error codes
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

// Common errors
var (
	ErrInvalidSiteKey   = errors.New("site key cannot be empty")
	ErrInvalidSecretKey = errors.New("secret key cannot be empty")
	ErrEmptyToken       = &VerificationError{Message: "turnstile response token cannot be empty"}
)

// isRetryableError determines if an error is retryable (network/temporary errors)
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

// VerifyRequest extracts the Turnstile token from an HTTP request and verifies it.
// It looks for the token in the "cf-turnstile-response" form field.
// The remote IP is automatically extracted from the request.
// An idempotency key is automatically generated for retry protection.
func (c *Client) VerifyRequest(ctx context.Context, req *http.Request) (*Response, error) {
	token := req.FormValue("cf-turnstile-response")

	// Extract IP from RemoteAddr (format is "IP:port")
	remoteIP := req.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	return c.VerifyToken(ctx, token, remoteIP)
}

// VerifyToken verifies a Turnstile token and returns the Cloudflare response.
// The remoteIP parameter is optional - omit it to exclude from verification.
// An idempotency key is automatically generated for retry protection.
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

// doVerifyRequest performs the actual HTTP request without retry logic
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

	var response Response
	if err := json.NewDecoder(result.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if !response.Success {
		return &response, createSpecificError(response.ErrorCodes)
	}

	return &response, nil
}
