// Package turnstile provides a simple, thread-safe client for verifying Cloudflare Turnstile CAPTCHA tokens.
package turnstile

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"
)

// MockResponse represents a configurable response for the mock client.
// Use this to customize what the mock client returns during testing.
type MockResponse struct {
	// Success indicates whether the verification should succeed
	Success bool
	// ChallengeTS is the timestamp of when the challenge was completed (ISO 8601 format)
	ChallengeTS string
	// Hostname is the hostname of the site where the challenge was completed
	Hostname string
	// ErrorCodes contains specific error codes when Success is false
	ErrorCodes []string
	// Action is the action name for this widget
	Action string
	// CData is the customer data passed to the widget
	CData string
}

// DefaultMockResponseSuccess is the default successful mock response.
var DefaultMockResponseSuccess = MockResponse{
	Success:     true,
	ChallengeTS: "2024-01-01T00:00:00Z",
	Hostname:    "example.com",
}

// DefaultMockResponseFail is the default failed mock response.
var DefaultMockResponseFail = MockResponse{
	Success:    false,
	ErrorCodes: []string{"invalid-input-response"},
}

// DefaultMockResponseTokenSpent is the default token-spent mock response.
var DefaultMockResponseTokenSpent = MockResponse{
	Success:    false,
	ErrorCodes: []string{"timeout-or-duplicate"},
}

// MockRoundTripper implements http.RoundTripper and intercepts all HTTP requests,
// returning configurable mock responses without making actual network calls.
// This is useful for unit testing where you want complete control over responses
// and don't want any external dependencies.
type MockRoundTripper struct {
	// Response is the mock response to return
	Response MockResponse

	// mu protects the call tracking fields
	mu sync.Mutex
	// callCount tracks how many times RoundTrip was called
	callCount int
	// lastRequest stores the last request for inspection
	lastRequest *http.Request
	// lastRequestBody stores the last request body (since it can only be read once)
	lastRequestBody []byte
}

// RoundTrip implements http.RoundTripper and returns a mock response.
func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	m.callCount++
	m.lastRequest = req

	// Read and store the request body for later inspection
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		m.lastRequestBody = body
		req.Body.Close()
	}
	m.mu.Unlock()

	// Build the JSON response
	respBody := Response{
		Success:     m.Response.Success,
		ChallengeTS: m.Response.ChallengeTS,
		Hostname:    m.Response.Hostname,
		ErrorCodes:  m.Response.ErrorCodes,
		Action:      m.Response.Action,
		CData:       m.Response.CData,
	}

	jsonBody, _ := json.Marshal(respBody)

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(bytes.NewReader(jsonBody)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// CallCount returns the number of times the mock was called.
func (m *MockRoundTripper) CallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

// LastRequest returns the last HTTP request made to the mock.
func (m *MockRoundTripper) LastRequest() *http.Request {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRequest
}

// LastRequestBody returns the body of the last HTTP request.
func (m *MockRoundTripper) LastRequestBody() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastRequestBody
}

// Reset clears the call count and last request.
func (m *MockRoundTripper) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount = 0
	m.lastRequest = nil
	m.lastRequestBody = nil
}

// SetResponse updates the mock response. This is safe for concurrent use.
func (m *MockRoundTripper) SetResponse(resp MockResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Response = resp
}

// MockClientOption is a function type used to configure a mock client.
type MockClientOption func(*MockRoundTripper)

// WithMockResponse configures the mock client to return a specific response.
func WithMockResponse(resp MockResponse) MockClientOption {
	return func(m *MockRoundTripper) {
		m.Response = resp
	}
}

// NewMockClient creates a new Turnstile client that never makes actual HTTP requests.
// Instead, it returns a configurable mock response. By default, it returns a successful
// verification response.
//
// This is useful for unit testing where you want:
//   - No network calls at all
//   - Complete control over the response
//   - The ability to inspect what requests were made
//
// The returned MockRoundTripper can be used to inspect calls and change responses.
//
// Example:
//
//	func TestMyHandler(t *testing.T) {
//		client, mock := turnstile.NewMockClient()
//
//		response, err := client.VerifyToken(context.Background(), "any-token")
//		if err != nil {
//			t.Fatalf("Expected successful verification: %v", err)
//		}
//
//		// Verify the mock was called
//		if mock.CallCount() != 1 {
//			t.Errorf("Expected 1 call, got %d", mock.CallCount())
//		}
//	}
func NewMockClient(opts ...MockClientOption) (*Client, *MockRoundTripper) {
	mock := &MockRoundTripper{
		Response: DefaultMockResponseSuccess,
	}

	for _, opt := range opts {
		opt(mock)
	}

	httpClient := &http.Client{
		Transport: mock,
		Timeout:   DefaultTimeout,
	}

	client, _ := New(
		"mock-site-key",
		"mock-secret-key",
		WithHTTPClient(httpClient),
		WithMaxRetries(0), // No retries for mock client by default
	)

	return client, mock
}

// NewMockClientAlwaysFail creates a mock client that always returns a verification failure.
// This is useful for testing error handling in your application.
//
// Example:
//
//	func TestMyHandlerFailure(t *testing.T) {
//		client, _ := turnstile.NewMockClientAlwaysFail()
//
//		_, err := client.VerifyToken(context.Background(), "any-token")
//		if err == nil {
//			t.Fatal("Expected verification to fail")
//		}
//
//		var invalidErr turnstile.ErrInvalidInputResponse
//		if !errors.As(err, &invalidErr) {
//			t.Fatalf("Expected ErrInvalidInputResponse, got %T", err)
//		}
//	}
func NewMockClientAlwaysFail(opts ...MockClientOption) (*Client, *MockRoundTripper) {
	allOpts := append([]MockClientOption{WithMockResponse(DefaultMockResponseFail)}, opts...)
	return NewMockClient(allOpts...)
}

// NewMockClientTokenSpent creates a mock client that returns a "token already spent" error.
// This simulates a replay attack scenario where a token has already been used.
//
// Example:
//
//	func TestMyHandlerDuplicateToken(t *testing.T) {
//		client, _ := turnstile.NewMockClientTokenSpent()
//
//		_, err := client.VerifyToken(context.Background(), "any-token")
//		var timeoutErr turnstile.ErrTimeoutOrDuplicate
//		if !errors.As(err, &timeoutErr) {
//			t.Fatal("Expected timeout-or-duplicate error")
//		}
//	}
func NewMockClientTokenSpent(opts ...MockClientOption) (*Client, *MockRoundTripper) {
	allOpts := append([]MockClientOption{WithMockResponse(DefaultMockResponseTokenSpent)}, opts...)
	return NewMockClient(allOpts...)
}

// NewMockClientWithResponse creates a mock client with a fully custom response.
// This gives you complete control over what the mock returns.
//
// Example:
//
//	func TestCustomScenario(t *testing.T) {
//		client, mock := turnstile.NewMockClientWithResponse(turnstile.MockResponse{
//			Success:     true,
//			ChallengeTS: time.Now().Format(time.RFC3339),
//			Hostname:    "myapp.example.com",
//			Action:      "login",
//		})
//
//		response, err := client.VerifyToken(context.Background(), "token")
//		if err != nil {
//			t.Fatalf("Unexpected error: %v", err)
//		}
//
//		if response.Action != "login" {
//			t.Errorf("Expected action 'login', got %q", response.Action)
//		}
//	}
func NewMockClientWithResponse(resp MockResponse, opts ...MockClientOption) (*Client, *MockRoundTripper) {
	allOpts := append([]MockClientOption{WithMockResponse(resp)}, opts...)
	return NewMockClient(allOpts...)
}

// MockHTTPError configures the mock to return an HTTP error response.
// This is useful for testing how your application handles HTTP-level failures.
type MockHTTPError struct {
	StatusCode int
	Status     string
}

// MockRoundTripperWithError implements http.RoundTripper and returns HTTP errors.
type MockRoundTripperWithError struct {
	*MockRoundTripper
	HTTPError *MockHTTPError
}

// RoundTrip implements http.RoundTripper and returns an HTTP error response.
func (m *MockRoundTripperWithError) RoundTrip(req *http.Request) (*http.Response, error) {
	m.MockRoundTripper.mu.Lock()
	m.MockRoundTripper.callCount++
	m.MockRoundTripper.lastRequest = req
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		m.MockRoundTripper.lastRequestBody = body
		req.Body.Close()
	}
	m.MockRoundTripper.mu.Unlock()

	if m.HTTPError != nil {
		return &http.Response{
			StatusCode: m.HTTPError.StatusCode,
			Status:     m.HTTPError.Status,
			Body:       io.NopCloser(bytes.NewReader([]byte{})),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}

	return m.MockRoundTripper.RoundTrip(req)
}

// NewMockClientWithHTTPError creates a mock client that returns HTTP-level errors.
// This is useful for testing how your application handles server errors, rate limiting, etc.
//
// Example:
//
//	func TestServerError(t *testing.T) {
//		client, _ := turnstile.NewMockClientWithHTTPError(500, "500 Internal Server Error")
//
//		_, err := client.VerifyToken(context.Background(), "token")
//		if err == nil {
//			t.Fatal("Expected error for 500 response")
//		}
//
//		if !strings.Contains(err.Error(), "500") {
//			t.Errorf("Expected error to mention 500, got: %v", err)
//		}
//	}
func NewMockClientWithHTTPError(statusCode int, status string) (*Client, *MockRoundTripperWithError) {
	baseMock := &MockRoundTripper{
		Response: DefaultMockResponseSuccess,
	}

	mock := &MockRoundTripperWithError{
		MockRoundTripper: baseMock,
		HTTPError: &MockHTTPError{
			StatusCode: statusCode,
			Status:     status,
		},
	}

	httpClient := &http.Client{
		Transport: mock,
		Timeout:   DefaultTimeout,
	}

	client, _ := New(
		"mock-site-key",
		"mock-secret-key",
		WithHTTPClient(httpClient),
		WithMaxRetries(0),
	)

	return client, mock
}

// Ensure MockRoundTripper implements http.RoundTripper at compile time
var _ http.RoundTripper = (*MockRoundTripper)(nil)
var _ http.RoundTripper = (*MockRoundTripperWithError)(nil)

// Compile-time check that mock functions are usable (verifies time package import)
var _ = time.Now
