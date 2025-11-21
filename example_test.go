package turnstile_test

import (
	"context"
	"errors"
	"fmt"
	"log"

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
