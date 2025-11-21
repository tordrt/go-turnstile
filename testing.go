// Package turnstile provides a simple, thread-safe client for verifying Cloudflare Turnstile CAPTCHA tokens.
package turnstile

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
