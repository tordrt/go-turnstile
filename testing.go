// Package turnstile provides a simple, thread-safe client for verifying Cloudflare Turnstile CAPTCHA tokens.
package turnstile

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

// Cloudflare provides dummy keys and tokens for testing Turnstile integrations.
// These keys allow you to test your implementation without setting up a real Turnstile widget.
// See: https://developers.cloudflare.com/turnstile/reference/testing/
const (
	// TestSiteKeyAlwaysPass is a dummy sitekey that always passes (visible widget).
	TestSiteKeyAlwaysPass = "1x00000000000000000000AA"

	// TestSiteKeyAlwaysBlock is a dummy sitekey that always blocks (visible widget).
	TestSiteKeyAlwaysBlock = "2x00000000000000000000AB"

	// TestSiteKeyAlwaysPassInvisible is a dummy sitekey that always passes (invisible widget).
	TestSiteKeyAlwaysPassInvisible = "1x00000000000000000000BB"

	// TestSiteKeyAlwaysBlockInvisible is a dummy sitekey that always blocks (invisible widget).
	TestSiteKeyAlwaysBlockInvisible = "2x00000000000000000000BB"

	// TestSiteKeyForceChallenge is a dummy sitekey that forces an interactive challenge.
	TestSiteKeyForceChallenge = "3x00000000000000000000FF"

	// TestSecretKeyAlwaysPass is a dummy secret key that always passes token verification.
	TestSecretKeyAlwaysPass = "1x0000000000000000000000000000000AA"

	// TestSecretKeyAlwaysFail is a dummy secret key that always fails token verification.
	TestSecretKeyAlwaysFail = "2x0000000000000000000000000000000AA"

	// TestSecretKeyTokenSpent is a dummy secret key that returns a "token already spent" error.
	TestSecretKeyTokenSpent = "3x0000000000000000000000000000000AA"

	// TestToken is a dummy response token that is accepted by all dummy secret keys.
	// Use this token when testing your server-side verification logic.
	TestToken = "XXXX.DUMMY.TOKEN.XXXX"
)

// NewTestClient creates a new Turnstile client configured for testing with Cloudflare's
// "always pass" dummy keys. This client will accept the TestToken and always return success.
//
// This is the recommended client for most testing scenarios where you want to verify that
// your handler correctly processes successful CAPTCHA verifications.
//
// Example:
//
//	func TestMyHandler(t *testing.T) {
//		client := turnstile.NewTestClient()
//		response, err := client.VerifyToken(context.Background(), turnstile.TestToken)
//		if err != nil {
//			t.Fatalf("Expected successful verification: %v", err)
//		}
//		// Test your handler logic with a valid token
//	}
func NewTestClient(opts ...ClientOption) *Client {
	client, _ := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass, opts...)
	return client
}

// NewTestClientAlwaysFail creates a new Turnstile client configured for testing with
// Cloudflare's "always fail" dummy keys. This client will reject all tokens including TestToken.
//
// Use this client to test error handling in your application when CAPTCHA verification fails.
//
// Example:
//
//	func TestMyHandlerFailure(t *testing.T) {
//		client := turnstile.NewTestClientAlwaysFail()
//		_, err := client.VerifyToken(context.Background(), turnstile.TestToken)
//		if err == nil {
//			t.Fatal("Expected verification to fail")
//		}
//		// Test your error handling logic
//	}
func NewTestClientAlwaysFail(opts ...ClientOption) *Client {
	client, _ := New(TestSiteKeyAlwaysBlock, TestSecretKeyAlwaysFail, opts...)
	return client
}

// NewTestClientTokenSpent creates a new Turnstile client configured for testing with
// Cloudflare's "token already spent" dummy key. This client will return a timeout-or-duplicate
// error, simulating a replay attack scenario.
//
// Use this client to test handling of duplicate token submissions in your application.
//
// Example:
//
//	func TestMyHandlerDuplicateToken(t *testing.T) {
//		client := turnstile.NewTestClientTokenSpent()
//		_, err := client.VerifyToken(context.Background(), turnstile.TestToken)
//		var timeoutErr turnstile.ErrTimeoutOrDuplicate
//		if !errors.As(err, &timeoutErr) {
//			t.Fatal("Expected timeout-or-duplicate error")
//		}
//		// Test your duplicate submission handling
//	}
func NewTestClientTokenSpent(opts ...ClientOption) *Client {
	client, _ := New(TestSiteKeyAlwaysPass, TestSecretKeyTokenSpent, opts...)
	return client
}

// NewTestRequest creates an HTTP POST request with the Turnstile test token included
// in the form data. This is useful for testing HTTP handlers that use VerifyRequest().
//
// The request includes:
//   - The "cf-turnstile-response" form field set to TestToken
//   - Any additional form fields provided in the formData parameter
//   - Proper Content-Type header (application/x-www-form-urlencoded)
//   - RemoteAddr set to "192.0.2.1:54321" (TEST-NET-1 reserved IP)
//
// Example:
//
//	func TestMyHTTPHandler(t *testing.T) {
//		client := turnstile.NewTestClient()
//
//		// Create a test request with the Turnstile token and additional form data
//		req := turnstile.NewTestRequest(map[string]string{
//			"username": "testuser",
//			"email":    "test@example.com",
//		})
//
//		// Use VerifyRequest to test your handler
//		response, err := client.VerifyRequest(req.Context(), req)
//		if err != nil {
//			t.Fatalf("Expected successful verification: %v", err)
//		}
//		// Continue testing your handler logic
//	}
func NewTestRequest(formData ...map[string]string) *http.Request {
	form := url.Values{}
	form.Set("cf-turnstile-response", TestToken)

	// Add any additional form fields
	if len(formData) > 0 {
		for key, value := range formData[0] {
			form.Set(key, value)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.0.2.1:54321" // TEST-NET-1 reserved IP address

	return req
}
