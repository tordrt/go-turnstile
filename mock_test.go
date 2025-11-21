package turnstile

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestNewMockClient(t *testing.T) {
	t.Run("creates client with default success response", func(t *testing.T) {
		client, mock := NewMockClient()

		if client == nil {
			t.Fatal("Expected client to be non-nil")
		}
		if mock == nil {
			t.Fatal("Expected mock to be non-nil")
		}

		response, err := client.VerifyToken(context.Background(), "any-token")
		if err != nil {
			t.Fatalf("Expected successful verification, got error: %v", err)
		}

		if !response.Success {
			t.Error("Expected response.Success to be true")
		}
		if mock.CallCount() != 1 {
			t.Errorf("Expected 1 call, got %d", mock.CallCount())
		}
	})

	t.Run("never makes actual HTTP requests", func(t *testing.T) {
		client, mock := NewMockClient()

		// This should not make any real HTTP request
		// If it did, it would likely fail or timeout since there's no real server
		response, err := client.VerifyToken(context.Background(), "test-token")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if !response.Success {
			t.Error("Expected mock to return success")
		}

		// Verify the mock intercepted the request
		if mock.CallCount() != 1 {
			t.Errorf("Expected mock to be called once, got %d", mock.CallCount())
		}
	})

	t.Run("accepts any token value", func(t *testing.T) {
		client, _ := NewMockClient()

		tokens := []string{
			"test-token",
			"XXXX.DUMMY.TOKEN.XXXX",
			"random-string-12345",
			"a",
		}

		for _, token := range tokens {
			response, err := client.VerifyToken(context.Background(), token)
			if err != nil {
				t.Errorf("Token %q: unexpected error: %v", token, err)
				continue
			}
			if !response.Success {
				t.Errorf("Token %q: expected success", token)
			}
		}
	})
}

func TestNewMockClientAlwaysFail(t *testing.T) {
	t.Run("always returns failure", func(t *testing.T) {
		client, mock := NewMockClientAlwaysFail()

		response, err := client.VerifyToken(context.Background(), "any-token")
		if err == nil {
			t.Fatal("Expected error, got nil")
		}

		if response != nil && response.Success {
			t.Error("Expected response.Success to be false")
		}

		// Should return ErrInvalidInputResponse
		var invalidErr *ErrInvalidInputResponse
		if !errors.As(err, &invalidErr) {
			t.Errorf("Expected ErrInvalidInputResponse, got %T: %v", err, err)
		}

		if mock.CallCount() != 1 {
			t.Errorf("Expected 1 call, got %d", mock.CallCount())
		}
	})
}

func TestNewMockClientTokenSpent(t *testing.T) {
	t.Run("returns timeout-or-duplicate error", func(t *testing.T) {
		client, mock := NewMockClientTokenSpent()

		response, err := client.VerifyToken(context.Background(), "any-token")
		if err == nil {
			t.Fatal("Expected error, got nil")
		}

		if response != nil && response.Success {
			t.Error("Expected response.Success to be false")
		}

		// Should return ErrTimeoutOrDuplicate
		var timeoutErr *ErrTimeoutOrDuplicate
		if !errors.As(err, &timeoutErr) {
			t.Errorf("Expected ErrTimeoutOrDuplicate, got %T: %v", err, err)
		}

		if mock.CallCount() != 1 {
			t.Errorf("Expected 1 call, got %d", mock.CallCount())
		}
	})
}

func TestNewMockClientWithResponse(t *testing.T) {
	t.Run("returns custom response", func(t *testing.T) {
		customResp := MockResponse{
			Success:     true,
			ChallengeTS: "2024-06-15T12:00:00Z",
			Hostname:    "myapp.example.com",
			Action:      "login",
			CData:       "custom-data",
		}

		client, mock := NewMockClientWithResponse(customResp)

		response, err := client.VerifyToken(context.Background(), "token")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if !response.Success {
			t.Error("Expected Success to be true")
		}
		if response.ChallengeTS != "2024-06-15T12:00:00Z" {
			t.Errorf("Expected ChallengeTS '2024-06-15T12:00:00Z', got %q", response.ChallengeTS)
		}
		if response.Hostname != "myapp.example.com" {
			t.Errorf("Expected Hostname 'myapp.example.com', got %q", response.Hostname)
		}
		if response.Action != "login" {
			t.Errorf("Expected Action 'login', got %q", response.Action)
		}
		if response.CData != "custom-data" {
			t.Errorf("Expected CData 'custom-data', got %q", response.CData)
		}

		if mock.CallCount() != 1 {
			t.Errorf("Expected 1 call, got %d", mock.CallCount())
		}
	})

	t.Run("returns custom error codes", func(t *testing.T) {
		customResp := MockResponse{
			Success:    false,
			ErrorCodes: []string{"bad-request"},
		}

		client, _ := NewMockClientWithResponse(customResp)

		_, err := client.VerifyToken(context.Background(), "token")
		if err == nil {
			t.Fatal("Expected error, got nil")
		}

		var badRequestErr *ErrBadRequest
		if !errors.As(err, &badRequestErr) {
			t.Errorf("Expected ErrBadRequest, got %T: %v", err, err)
		}
	})
}

func TestMockRoundTripper_CallTracking(t *testing.T) {
	t.Run("tracks multiple calls", func(t *testing.T) {
		client, mock := NewMockClient()

		if mock.CallCount() != 0 {
			t.Errorf("Expected 0 calls initially, got %d", mock.CallCount())
		}

		for i := 1; i <= 5; i++ {
			_, _ = client.VerifyToken(context.Background(), "token")
			if mock.CallCount() != i {
				t.Errorf("After %d calls, expected count %d, got %d", i, i, mock.CallCount())
			}
		}
	})

	t.Run("reset clears call count", func(t *testing.T) {
		client, mock := NewMockClient()

		_, _ = client.VerifyToken(context.Background(), "token")
		_, _ = client.VerifyToken(context.Background(), "token")

		if mock.CallCount() != 2 {
			t.Errorf("Expected 2 calls, got %d", mock.CallCount())
		}

		mock.Reset()

		if mock.CallCount() != 0 {
			t.Errorf("Expected 0 calls after reset, got %d", mock.CallCount())
		}
	})

	t.Run("tracks last request", func(t *testing.T) {
		client, mock := NewMockClient()

		_, _ = client.VerifyToken(context.Background(), "test-token-123")

		lastReq := mock.LastRequest()
		if lastReq == nil {
			t.Fatal("Expected LastRequest to be non-nil")
		}

		if lastReq.Method != "POST" {
			t.Errorf("Expected POST method, got %s", lastReq.Method)
		}
	})

	t.Run("tracks last request body", func(t *testing.T) {
		client, mock := NewMockClient()

		_, _ = client.VerifyToken(context.Background(), "test-token-123")

		body := mock.LastRequestBody()
		if len(body) == 0 {
			t.Fatal("Expected LastRequestBody to be non-empty")
		}

		bodyStr := string(body)
		if !strings.Contains(bodyStr, "test-token-123") {
			t.Error("Expected request body to contain the token")
		}
	})
}

func TestMockRoundTripper_SetResponse(t *testing.T) {
	t.Run("can change response dynamically", func(t *testing.T) {
		client, mock := NewMockClient()

		// First call should succeed
		response, err := client.VerifyToken(context.Background(), "token")
		if err != nil {
			t.Fatalf("Expected success, got error: %v", err)
		}
		if !response.Success {
			t.Error("Expected first call to succeed")
		}

		// Change to failure response
		mock.SetResponse(MockResponse{
			Success:    false,
			ErrorCodes: []string{"invalid-input-response"},
		})

		// Second call should fail
		response, err = client.VerifyToken(context.Background(), "token")
		if err == nil {
			t.Fatal("Expected error after SetResponse, got nil")
		}
		if response != nil && response.Success {
			t.Error("Expected second call to fail")
		}
	})
}

func TestNewMockClientWithHTTPError(t *testing.T) {
	t.Run("returns 500 error", func(t *testing.T) {
		client, mock := NewMockClientWithHTTPError(500, "500 Internal Server Error")

		_, err := client.VerifyToken(context.Background(), "token")
		if err == nil {
			t.Fatal("Expected error for 500 response, got nil")
		}

		if !strings.Contains(err.Error(), "500") {
			t.Errorf("Expected error to mention 500, got: %v", err)
		}

		if mock.CallCount() != 1 {
			t.Errorf("Expected 1 call, got %d", mock.CallCount())
		}
	})

	t.Run("returns 429 rate limit error", func(t *testing.T) {
		client, _ := NewMockClientWithHTTPError(429, "429 Too Many Requests")

		_, err := client.VerifyToken(context.Background(), "token")
		if err == nil {
			t.Fatal("Expected error for 429 response, got nil")
		}

		if !strings.Contains(err.Error(), "429") {
			t.Errorf("Expected error to mention 429, got: %v", err)
		}
	})

	t.Run("returns 503 service unavailable", func(t *testing.T) {
		client, _ := NewMockClientWithHTTPError(503, "503 Service Unavailable")

		_, err := client.VerifyToken(context.Background(), "token")
		if err == nil {
			t.Fatal("Expected error for 503 response, got nil")
		}

		if !strings.Contains(err.Error(), "503") {
			t.Errorf("Expected error to mention 503, got: %v", err)
		}
	})
}

func TestMockClient_WithVerifyRequest(t *testing.T) {
	t.Run("works with VerifyRequest", func(t *testing.T) {
		client, mock := NewMockClient()

		req := NewTestRequest(map[string]string{
			"username": "testuser",
		})

		response, err := client.VerifyRequest(context.Background(), req)
		if err != nil {
			t.Fatalf("VerifyRequest failed: %v", err)
		}

		if !response.Success {
			t.Error("Expected successful verification")
		}

		if mock.CallCount() != 1 {
			t.Errorf("Expected 1 call, got %d", mock.CallCount())
		}
	})

	t.Run("mock failure with VerifyRequest", func(t *testing.T) {
		client, _ := NewMockClientAlwaysFail()

		req := NewTestRequest()

		_, err := client.VerifyRequest(context.Background(), req)
		if err == nil {
			t.Fatal("Expected error, got nil")
		}
	})
}

func TestMockClient_ConcurrentAccess(t *testing.T) {
	t.Run("safe for concurrent use", func(t *testing.T) {
		client, mock := NewMockClient()

		done := make(chan bool)
		for i := 0; i < 10; i++ {
			go func() {
				_, _ = client.VerifyToken(context.Background(), "token")
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		if mock.CallCount() != 10 {
			t.Errorf("Expected 10 calls, got %d", mock.CallCount())
		}
	})

	t.Run("SetResponse safe during concurrent access", func(t *testing.T) {
		client, mock := NewMockClient()

		done := make(chan bool)

		// Concurrent reads
		for i := 0; i < 5; i++ {
			go func() {
				_, _ = client.VerifyToken(context.Background(), "token")
				done <- true
			}()
		}

		// Concurrent writes
		for i := 0; i < 5; i++ {
			go func() {
				mock.SetResponse(MockResponse{Success: true})
				done <- true
			}()
		}

		for i := 0; i < 10; i++ {
			<-done
		}

		// Just verify it didn't panic or deadlock
		if mock.CallCount() < 5 {
			t.Errorf("Expected at least 5 calls, got %d", mock.CallCount())
		}
	})
}

func TestMockClientOption_WithMockResponse(t *testing.T) {
	t.Run("configure mock at creation time", func(t *testing.T) {
		customResp := MockResponse{
			Success:     true,
			ChallengeTS: "2024-01-01T00:00:00Z",
			Hostname:    "test.example.com",
			Action:      "signup",
		}

		client, _ := NewMockClient(WithMockResponse(customResp))

		response, err := client.VerifyToken(context.Background(), "token")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		if response.Hostname != "test.example.com" {
			t.Errorf("Expected Hostname 'test.example.com', got %q", response.Hostname)
		}
		if response.Action != "signup" {
			t.Errorf("Expected Action 'signup', got %q", response.Action)
		}
	})
}

func TestMockClient_NoRetries(t *testing.T) {
	t.Run("mock client has no retries by default", func(t *testing.T) {
		// Create a mock that fails with an error that would normally be retried
		client, mock := NewMockClientWithHTTPError(500, "500 Internal Server Error")

		_, _ = client.VerifyToken(context.Background(), "token")

		// Should only be called once (no retries)
		if mock.CallCount() != 1 {
			t.Errorf("Expected exactly 1 call (no retries), got %d", mock.CallCount())
		}
	})
}

// TestMockVsTestClient documents the difference between mock and test clients
func TestMockVsTestClient(t *testing.T) {
	t.Run("mock client does not make real requests", func(t *testing.T) {
		// This test verifies that the mock client doesn't hit any real endpoint
		client, mock := NewMockClient()

		// Even with a bogus token, it succeeds because we're mocking
		response, err := client.VerifyToken(context.Background(), "completely-fake-token")
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !response.Success {
			t.Error("Mock should return success regardless of token")
		}

		// Verify we captured the request
		if mock.LastRequest() == nil {
			t.Error("Expected to capture the request")
		}
	})
}
