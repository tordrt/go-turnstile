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
