package turnstile_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/tordrt/go-turnstile"
)

// ExampleNew demonstrates basic usage of the Turnstile client
func ExampleNew() {
	client, err := turnstile.New("your-site-key", "your-secret-key")
	if err != nil {
		log.Fatal(err)
	}

	// Verify a token from a form submission
	valid, err := client.VerifyToken(context.Background(), "token-from-form", "")
	if err != nil {
		log.Printf("Verification failed: %v", err)
		return
	}

	if valid {
		fmt.Println("Token is valid!")
	} else {
		fmt.Println("Token is invalid!")
	}
}

// ExampleNew_withOptions demonstrates using client options
func ExampleNew_withOptions() {
	client, err := turnstile.New("your-site-key", "your-secret-key",
		turnstile.WithTimeout(15*time.Second),
		turnstile.WithVerifyEndpoint("https://custom.example.com/verify"),
	)
	if err != nil {
		log.Fatal(err)
	}

	// Verify with remote IP
	valid, err := client.VerifyToken(context.Background(), "token-from-form", "192.168.1.1")
	if err != nil {
		log.Printf("Verification failed: %v", err)
		return
	}

	if valid {
		fmt.Println("Token is valid!")
	} else {
		fmt.Println("Token is invalid!")
	}
}

// ExampleClient_VerifyToken demonstrates token verification with error handling
func ExampleClient_VerifyToken() {
	client, err := turnstile.New("your-site-key", "your-secret-key")
	if err != nil {
		log.Fatal(err)
	}

	token := "cf-turnstile-response-token"

	valid, err := client.VerifyToken(context.Background(), token, "")
	if err != nil {
		// Handle different types of errors
		var verifyErr *turnstile.VerificationError
		if errors.As(err, &verifyErr) {
			if len(verifyErr.ErrorCodes) > 0 {
				fmt.Printf("Verification failed with error codes: %v\n", verifyErr.ErrorCodes)
			} else {
				fmt.Printf("Verification failed: %s\n", verifyErr.Message)
			}
		} else {
			fmt.Printf("Request failed: %v\n", err)
		}
		return
	}

	if valid {
		fmt.Println("CAPTCHA verification successful")
		// Proceed with form processing
	} else {
		fmt.Println("CAPTCHA verification failed")
		// Show error to user
	}
}
