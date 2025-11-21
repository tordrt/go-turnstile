package turnstile_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/tordrt/go-turnstile"
)

// ExampleNew demonstrates basic usage of the Turnstile client
func ExampleNew() {
	turnstileClient, err := turnstile.New("your-site-key", "your-secret-key")
	if err != nil {
		log.Fatal(err)
	}

	// Verify a token from a form submission (no IP)
	// Using _ to ignore response since validation is confirmed by nil error
	_, err = turnstileClient.VerifyToken(context.TODO(), "token-from-form")
	if err != nil {
		log.Printf("Verification failed: %v", err)
		return
	}

	// If no error, token is valid
	fmt.Println("Token is valid!")
	// Note: You can capture the response if you need access to additional fields like ChallengeTS, Hostname, etc.
}

// ExampleNew_withOptions demonstrates using client options
func ExampleNew_withOptions() {
	turnstileClient, err := turnstile.New("your-site-key", "your-secret-key",
		turnstile.WithVerifyEndpoint("https://custom.example.com/verify"),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Verify with remote IP
	// Using _ to ignore response since validation is confirmed by nil error
	_, err = turnstileClient.VerifyToken(context.TODO(), "token-from-form", "192.168.1.1")
	if err != nil {
		log.Printf("Verification failed: %v", err)
		return
	}

	// If no error, token is valid
	fmt.Println("Token is valid!")
	// Note: You can capture the response if you need access to additional fields like ChallengeTS, Hostname, etc.
}

// ExampleClient_VerifyToken demonstrates token verification with error handling
func ExampleClient_VerifyToken() {
	turnstileClient, err := turnstile.New("your-site-key", "your-secret-key")
	if err != nil {
		log.Fatal(err)
	}

	token := "cf-turnstile-response-token"

	// Using _ to ignore response since validation is confirmed by nil error
	_, err = turnstileClient.VerifyToken(context.TODO(), token)
	if err != nil {
		// Handle specific error types
		switch {
		case errors.As(err, &turnstile.ErrMissingInputSecret{}):
			fmt.Println("Missing secret key")
		case errors.As(err, &turnstile.ErrInvalidInputSecret{}):
			fmt.Println("Invalid secret key")
		case errors.As(err, &turnstile.ErrMissingInputResponse{}):
			fmt.Println("Missing token")
		case errors.As(err, &turnstile.ErrInvalidInputResponse{}):
			fmt.Println("Invalid or expired token")
		case errors.As(err, &turnstile.ErrTimeoutOrDuplicate{}):
			fmt.Println("Token timeout or duplicate submission")
		case errors.As(err, &turnstile.ErrInternalError{}):
			fmt.Println("Cloudflare internal error")
		default:
			fmt.Printf("Request failed: %v\n", err)
		}
		return
	}

	// If no error, token is valid
	fmt.Println("CAPTCHA verification successful")
	// Proceed with form processing
}

// This example demonstrates how to use the test client for unit testing.
// This is the recommended approach for testing your Turnstile handler code.
//
// Note: This example uses test keys that interact with Cloudflare's real endpoint,
// so it's shown for demonstration purposes only.
func ExampleNewTestClient() {
	// Create a test client that always passes verification
	testClient := turnstile.NewTestClient()

	// Use the test token provided by Cloudflare
	// In your real tests, you would use this in your handler test code
	response, err := testClient.VerifyToken(context.Background(), turnstile.TestToken)
	if err != nil {
		// In real usage, handle errors appropriately
		log.Printf("Verification error: %v", err)
		return
	}

	fmt.Printf("Test verification successful: %v\n", response.Success)
}

// This example demonstrates testing error handling when Turnstile verification fails.
//
// Note: This example uses test keys that interact with Cloudflare's real endpoint,
// so it's shown for demonstration purposes only.
func ExampleNewTestClientAlwaysFail() {
	// Create a test client that always fails verification
	testClient := turnstile.NewTestClientAlwaysFail()

	// This will fail even with the test token
	_, err := testClient.VerifyToken(context.Background(), turnstile.TestToken)
	if err != nil {
		fmt.Println("Verification failed as expected")
		// Test your error handling code here
	}
}

// This example demonstrates testing duplicate token handling.
//
// Note: This example uses test keys that interact with Cloudflare's real endpoint,
// so it's shown for demonstration purposes only.
func ExampleNewTestClientTokenSpent() {
	// Create a test client that simulates "token already spent" errors
	testClient := turnstile.NewTestClientTokenSpent()

	_, err := testClient.VerifyToken(context.Background(), turnstile.TestToken)
	if err != nil {
		var timeoutErr turnstile.ErrTimeoutOrDuplicate
		if errors.As(err, &timeoutErr) {
			fmt.Println("Detected duplicate token submission")
			// Test your duplicate submission handling here
		}
	}
}

// This example demonstrates how to use NewTestRequest to test HTTP handlers
// that use VerifyRequest(). This is the easiest way to test handlers that
// process form submissions with Turnstile tokens.
//
// Note: This example uses test keys that interact with Cloudflare's real endpoint,
// so it's shown for demonstration purposes only.
func ExampleNewTestRequest() {
	// Create a test client
	testClient := turnstile.NewTestClient()

	// Create a test request with the Turnstile token already included
	// You can also add additional form fields
	req := turnstile.NewTestRequest(map[string]string{
		"username": "testuser",
		"email":    "test@example.com",
	})

	// Verify the request - the test token is already in the request
	response, err := testClient.VerifyRequest(context.Background(), req)
	if err != nil {
		log.Printf("Verification error: %v", err)
		return
	}

	fmt.Printf("Verification successful: %v\n", response.Success)
}

// This example demonstrates how to use AddTestToken to add the Turnstile
// test token to an existing HTTP request. This is useful when you already
// have a request object from your test setup.
//
// Note: This example uses test keys that interact with Cloudflare's real endpoint,
// so it's shown for demonstration purposes only.
func ExampleAddTestToken() {
	// Create a test client
	testClient := turnstile.NewTestClient()

	// Suppose you already have a request from your test framework
	form := url.Values{}
	form.Set("username", "testuser")
	form.Set("email", "test@example.com")

	req := httptest.NewRequest(http.MethodPost, "/submit", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add the test token to the existing request
	err := turnstile.AddTestToken(req)
	if err != nil {
		log.Printf("Failed to add test token: %v", err)
		return
	}

	// Now verify the request
	response, err := testClient.VerifyRequest(context.Background(), req)
	if err != nil {
		log.Printf("Verification error: %v", err)
		return
	}

	fmt.Printf("Verification successful: %v\n", response.Success)
}

// This example demonstrates using the mock client for unit testing
// without making any HTTP requests. This is useful for fast, isolated
// tests or in environments without network access.
func ExampleNewMockClient() {
	// Create a mock client - no HTTP requests are made
	client, mock := turnstile.NewMockClient()

	// Any token value works - responses are fully mocked
	response, err := client.VerifyToken(context.Background(), "any-token-value")
	if err != nil {
		log.Printf("Verification error: %v", err)
		return
	}

	fmt.Printf("Mock verification successful: %v\n", response.Success)
	fmt.Printf("Mock was called %d time(s)\n", mock.CallCount())
	// Output:
	// Mock verification successful: true
	// Mock was called 1 time(s)
}

// This example demonstrates using the mock client that always fails.
func ExampleNewMockClientAlwaysFail() {
	// Create a mock client that always fails
	client, _ := turnstile.NewMockClientAlwaysFail()

	_, err := client.VerifyToken(context.Background(), "any-token")
	if err != nil {
		fmt.Println("Mock verification failed as expected")

		var invalidErr *turnstile.ErrInvalidInputResponse
		if errors.As(err, &invalidErr) {
			fmt.Println("Error type: ErrInvalidInputResponse")
		}
	}
	// Output:
	// Mock verification failed as expected
	// Error type: ErrInvalidInputResponse
}

// This example demonstrates using the mock client that returns token-spent errors.
func ExampleNewMockClientTokenSpent() {
	// Create a mock client that simulates "token already spent" errors
	client, _ := turnstile.NewMockClientTokenSpent()

	_, err := client.VerifyToken(context.Background(), "any-token")
	if err != nil {
		var timeoutErr *turnstile.ErrTimeoutOrDuplicate
		if errors.As(err, &timeoutErr) {
			fmt.Println("Detected duplicate token (mocked)")
		}
	}
	// Output:
	// Detected duplicate token (mocked)
}

// This example demonstrates creating a mock client with a custom response.
func ExampleNewMockClientWithResponse() {
	// Create a mock with a custom response
	client, _ := turnstile.NewMockClientWithResponse(turnstile.MockResponse{
		Success:     true,
		ChallengeTS: "2024-06-15T12:00:00Z",
		Hostname:    "myapp.example.com",
		Action:      "login",
	})

	response, err := client.VerifyToken(context.Background(), "token")
	if err != nil {
		log.Printf("Error: %v", err)
		return
	}

	fmt.Printf("Success: %v\n", response.Success)
	fmt.Printf("Hostname: %s\n", response.Hostname)
	fmt.Printf("Action: %s\n", response.Action)
	// Output:
	// Success: true
	// Hostname: myapp.example.com
	// Action: login
}

// This example demonstrates changing mock behavior dynamically.
func ExampleMockRoundTripper_SetResponse() {
	client, mock := turnstile.NewMockClient()

	// First call succeeds
	response, _ := client.VerifyToken(context.Background(), "token")
	fmt.Printf("First call success: %v\n", response.Success)

	// Change to failure mode
	mock.SetResponse(turnstile.MockResponse{
		Success:    false,
		ErrorCodes: []string{"invalid-input-response"},
	})

	// Second call fails
	_, err := client.VerifyToken(context.Background(), "token")
	fmt.Printf("Second call failed: %v\n", err != nil)
	// Output:
	// First call success: true
	// Second call failed: true
}

// This example demonstrates testing HTTP-level errors with the mock client.
func ExampleNewMockClientWithHTTPError() {
	// Create a mock that returns a 500 error
	client, _ := turnstile.NewMockClientWithHTTPError(500, "500 Internal Server Error")

	_, err := client.VerifyToken(context.Background(), "token")
	if err != nil {
		fmt.Println("HTTP error simulated successfully")
	}
	// Output:
	// HTTP error simulated successfully
}
