package turnstile

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Cloudflare dummy keys for testing
// See: https://developers.cloudflare.com/turnstile/reference/testing/
const (
	// Dummy sitekeys
	DummySiteKeyAlwaysPass     = "1x00000000000000000000AA" // Always passes (visible)
	DummySiteKeyAlwaysBlock    = "2x00000000000000000000AB" // Always blocks (visible)
	DummySiteKeyAlwaysPassInv  = "1x00000000000000000000BB" // Always passes (invisible)
	DummySiteKeyAlwaysBlockInv = "2x00000000000000000000BB" // Always blocks (invisible)
	DummySiteKeyForceChallenge = "3x00000000000000000000FF" // Forces interactive challenge

	// Dummy secret keys
	DummySecretKeyAlwaysPass = "1x0000000000000000000000000000000AA" // Always passes
	DummySecretKeyAlwaysFail = "2x0000000000000000000000000000000AA" // Always fails
	DummySecretKeyTokenSpent = "3x0000000000000000000000000000000AA" // "token already spent" error

	// Dummy response token - only accepted by dummy secret keys
	DummyToken = "XXXX.DUMMY.TOKEN.XXXX"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		siteKey   string
		secretKey string
		wantErr   bool
	}{
		{
			name:      "valid keys with dummy always-pass",
			siteKey:   DummySiteKeyAlwaysPass,
			secretKey: DummySecretKeyAlwaysPass,
			wantErr:   false,
		},
		{
			name:      "empty site key",
			siteKey:   "",
			secretKey: DummySecretKeyAlwaysPass,
			wantErr:   true,
		},
		{
			name:      "empty secret key",
			siteKey:   DummySiteKeyAlwaysPass,
			secretKey: "",
			wantErr:   true,
		},
		{
			name:      "whitespace keys",
			siteKey:   "   ",
			secretKey: "   ",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := New(tt.siteKey, tt.secretKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("New() returned nil client without error")
			}
		})
	}
}

func TestClientOptions(t *testing.T) {
	t.Run("WithHTTPClient", func(t *testing.T) {
		customClient := &http.Client{Timeout: 5 * time.Second}
		client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass,
			WithHTTPClient(customClient),
		)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		if client.client != customClient {
			t.Error("WithHTTPClient() did not set custom HTTP client")
		}
	})

	t.Run("WithTimeout", func(t *testing.T) {
		customTimeout := 15 * time.Second
		client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass,
			WithTimeout(customTimeout),
		)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		if client.client.Timeout != customTimeout {
			t.Errorf("WithTimeout() got %v, want %v", client.client.Timeout, customTimeout)
		}
	})

	t.Run("WithVerifyEndpoint", func(t *testing.T) {
		customEndpoint := "https://custom.example.com/verify"
		client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass,
			WithVerifyEndpoint(customEndpoint),
		)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		if client.verifyURL != customEndpoint {
			t.Errorf("WithVerifyEndpoint() got %s, want %s", client.verifyURL, customEndpoint)
		}
	})

	t.Run("multiple options", func(t *testing.T) {
		customClient := &http.Client{Timeout: 5 * time.Second}
		customTimeout := 15 * time.Second
		customEndpoint := "https://custom.example.com/verify"

		client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass,
			WithHTTPClient(customClient),
			WithTimeout(customTimeout),
			WithVerifyEndpoint(customEndpoint),
		)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		if client.client != customClient {
			t.Error("WithHTTPClient() did not set custom HTTP client")
		}
		if client.client.Timeout != customTimeout {
			t.Errorf("WithTimeout() got %v, want %v", client.client.Timeout, customTimeout)
		}
		if client.verifyURL != customEndpoint {
			t.Errorf("WithVerifyEndpoint() got %s, want %s", client.verifyURL, customEndpoint)
		}
	})
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		remoteIP       string
		responseStatus int
		responseBody   string
		wantValid      bool
		wantErr        bool
	}{
		{
			name:           "dummy valid token",
			token:          DummyToken,
			responseStatus: 200,
			responseBody:   `{"success": true}`,
			wantValid:      true,
			wantErr:        false,
		},
		{
			name:           "invalid token with always-fail dummy secret",
			token:          DummyToken,
			responseStatus: 200,
			responseBody:   `{"success": false, "error-codes": ["invalid-input-secret"]}`,
			wantValid:      false,
			wantErr:        true,
		},
		{
			name:           "empty token",
			token:          "",
			responseStatus: 200,
			responseBody:   `{"success": false}`,
			wantValid:      false,
			wantErr:        true,
		},
		{
			name:           "dummy token with remote IP",
			token:          DummyToken,
			remoteIP:       "192.168.1.1",
			responseStatus: 200,
			responseBody:   `{"success": true}`,
			wantValid:      true,
			wantErr:        false,
		},
		{
			name:           "malformed JSON response",
			token:          "valid-token",
			responseStatus: 200,
			responseBody:   `{"success": true`,
			wantValid:      false,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}

				if err := r.ParseMultipartForm(32 << 20); err != nil {
					t.Errorf("Failed to parse multipart form: %v", err)
				}

				if tt.remoteIP != "" {
					if r.FormValue("remoteip") != tt.remoteIP {
						t.Errorf("Expected remoteip %s, got %s", tt.remoteIP, r.FormValue("remoteip"))
					}
				}

				w.WriteHeader(tt.responseStatus)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass,
				WithVerifyEndpoint(server.URL),
			)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			valid, err := client.VerifyToken(context.Background(), tt.token, tt.remoteIP)

			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if valid != tt.wantValid {
				t.Errorf("Verify() valid = %v, wantValid %v", valid, tt.wantValid)
			}

			// Check if error is of correct type when expected
			if tt.wantErr && err != nil {
				switch {
				case tt.token == "":
					if !errors.Is(err, ErrEmptyToken) {
						t.Errorf("Expected ErrEmptyToken, got %v", err)
					}
				case strings.Contains(tt.responseBody, "error-codes"):
					var verificationErr *VerificationError
					if !errors.As(err, &verificationErr) {
						t.Errorf("Expected VerificationError, got %T", err)
					}
				}
			}
		})
	}
}

func TestVerificationError(t *testing.T) {
	tests := []struct {
		name       string
		err        *VerificationError
		wantString string
	}{
		{
			name:       "error without codes",
			err:        &VerificationError{Message: "test error"},
			wantString: "test error",
		},
		{
			name: "error with codes",
			err: &VerificationError{
				Message:    "verification failed",
				ErrorCodes: []string{"invalid-input-response", "timeout-or-duplicate"},
			},
			wantString: "verification failed: [invalid-input-response timeout-or-duplicate]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.wantString {
				t.Errorf("VerificationError.Error() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// TestHTTPErrors tests various HTTP-level failures
func TestHTTPErrors(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		responseBody   string
		wantErr        bool
	}{
		{
			name:           "server error 500",
			responseStatus: 500,
			responseBody:   `{"success": false}`,
			wantErr:        true, // Server returning success: false should result in verification error
		},
		{
			name:           "invalid JSON response",
			responseStatus: 200,
			responseBody:   `invalid json`,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.responseStatus)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass,
				WithVerifyEndpoint(server.URL),
			)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			_, err = client.VerifyToken(context.Background(), DummyToken, "192.168.1.1")

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestContextCancellation tests context cancellation during verification
func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Simulate slow response
		w.WriteHeader(200)
		w.Write([]byte(`{"success": true}`))
	}))
	defer server.Close()

	client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass,
		WithVerifyEndpoint(server.URL),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = client.VerifyToken(ctx, DummyToken, "192.168.1.1")
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}
}

// TestIPExtraction tests the IP extraction logic in VerifyRequest
func TestIPExtraction(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "X-Forwarded-For single IP",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "X-Forwarded-For multiple IPs",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 198.51.100.1, 192.168.1.1"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "203.0.113.1",
		},
		{
			name:       "X-Real-IP header",
			headers:    map[string]string{"X-Real-IP": "203.0.113.2"},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "203.0.113.2",
		},
		{
			name:       "RemoteAddr only",
			headers:    map[string]string{},
			remoteAddr: "203.0.113.3:54321",
			expectedIP: "203.0.113.3",
		},
		{
			name:       "IPv6 RemoteAddr",
			headers:    map[string]string{},
			remoteAddr: "[2001:db8::1]:54321",
			expectedIP: "[2001:db8::1]",
		},
		{
			name:       "X-Forwarded-For takes precedence over X-Real-IP",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1",
				"X-Real-IP":       "203.0.113.2",
			},
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedIP string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseMultipartForm(32 << 20); err != nil {
					t.Errorf("Failed to parse multipart form: %v", err)
					return
				}
				receivedIP = r.FormValue("remoteip")
				w.WriteHeader(200)
				w.Write([]byte(`{"success": true}`))
			}))
			defer server.Close()

			client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass,
				WithVerifyEndpoint(server.URL),
			)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			// Create request with turnstile token
			formData := strings.NewReader("cf-turnstile-response=" + DummyToken)
			req := httptest.NewRequest(http.MethodPost, "/test", formData)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = tt.remoteAddr

			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			_, err = client.VerifyRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("VerifyRequest() failed: %v", err)
			}

			if receivedIP != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, receivedIP)
			}
		})
	}
}

func TestVerifyRequest(t *testing.T) {
	tests := []struct {
		name           string
		formData       map[string]string
		headers        map[string]string
		remoteAddr     string
		responseStatus int
		responseBody   string
		wantValid      bool
		wantErr        bool
	}{
		{
			name: "valid request with turnstile token",
			formData: map[string]string{
				"cf-turnstile-response": DummyToken,
			},
			responseStatus: 200,
			responseBody:   `{"success": true}`,
			wantValid:      true,
			wantErr:        false,
		},
		{
			name: "request without turnstile token",
			formData: map[string]string{
				"other-field": "value",
			},
			responseStatus: 200,
			responseBody:   `{"success": false}`,
			wantValid:      false,
			wantErr:        true,
		},
		{
			name:           "request with empty form",
			formData:       map[string]string{},
			responseStatus: 200,
			responseBody:   `{"success": false}`,
			wantValid:      false,
			wantErr:        true,
		},
		{
			name: "request with empty turnstile token",
			formData: map[string]string{
				"cf-turnstile-response": "",
			},
			responseStatus: 200,
			responseBody:   `{"success": false}`,
			wantValid:      false,
			wantErr:        true,
		},
		{
			name: "request with multiple form fields",
			formData: map[string]string{
				"cf-turnstile-response": DummyToken,
				"username":              "test",
				"email":                 "test@example.com",
			},
			responseStatus: 200,
			responseBody:   `{"success": true}`,
			wantValid:      true,
			wantErr:        false,
		},
		{
			name: "request with X-Forwarded-For header",
			formData: map[string]string{
				"cf-turnstile-response": DummyToken,
			},
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.1, 198.51.100.1",
			},
			responseStatus: 200,
			responseBody:   `{"success": true}`,
			wantValid:      true,
			wantErr:        false,
		},
		{
			name: "request with X-Real-IP header",
			formData: map[string]string{
				"cf-turnstile-response": DummyToken,
			},
			headers: map[string]string{
				"X-Real-IP": "203.0.113.2",
			},
			responseStatus: 200,
			responseBody:   `{"success": true}`,
			wantValid:      true,
			wantErr:        false,
		},
		{
			name: "request with RemoteAddr",
			formData: map[string]string{
				"cf-turnstile-response": DummyToken,
			},
			remoteAddr:     "203.0.113.3:54321",
			responseStatus: 200,
			responseBody:   `{"success": true}`,
			wantValid:      true,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}

				if err := r.ParseForm(); err != nil {
					t.Errorf("Failed to parse form: %v", err)
				}

				w.WriteHeader(tt.responseStatus)
				w.Write([]byte(tt.responseBody))
			}))
			defer server.Close()

			client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass,
				WithVerifyEndpoint(server.URL),
			)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			// Create a request with form data
			formData := strings.NewReader("")
			if len(tt.formData) > 0 {
				var parts []string
				for key, value := range tt.formData {
					parts = append(parts, key+"="+value)
				}
				formData = strings.NewReader(strings.Join(parts, "&"))
			}

			req := httptest.NewRequest(http.MethodPost, "/test", formData)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			// Set custom headers if provided
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Set custom RemoteAddr if provided
			if tt.remoteAddr != "" {
				req.RemoteAddr = tt.remoteAddr
			}

			valid, err := client.VerifyRequest(context.Background(), req)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if valid != tt.wantValid {
				t.Errorf("VerifyRequest() valid = %v, wantValid %v", valid, tt.wantValid)
			}

			// Check if error is of correct type when expected
			if tt.wantErr && err != nil {
				token := req.FormValue("cf-turnstile-response")
				if token == "" && !errors.Is(err, ErrEmptyToken) {
					t.Errorf("Expected ErrEmptyToken for missing token, got %v", err)
				}
			}
		})
	}
}

// Integration tests that make real API calls to Cloudflare's test endpoint
// These tests require internet connectivity and may be slower

func TestIntegration_AlwaysPass(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	valid, err := client.VerifyToken(context.Background(), DummyToken, "")
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}

	if !valid {
		t.Error("Expected token to be valid with always-pass test key")
	}
}

func TestIntegration_AlwaysFail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(DummySiteKeyAlwaysBlock, DummySecretKeyAlwaysFail)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	valid, err := client.VerifyToken(context.Background(), DummyToken, "")
	if err == nil {
		t.Fatal("Expected error for always-fail secret key")
	}

	if valid {
		t.Error("Expected token to be invalid with always-fail secret key")
	}

	var verifyErr *VerificationError
	if !errors.As(err, &verifyErr) {
		t.Errorf("Expected VerificationError, got %T", err)
	}
}

func TestIntegration_TokenAlreadySpent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyTokenSpent)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	valid, err := client.VerifyToken(context.Background(), DummyToken, "")
	if err == nil {
		t.Fatal("Expected 'token already spent' error")
	}

	if valid {
		t.Error("Expected token to be invalid for 'token already spent' scenario")
	}

	var verifyErr *VerificationError
	if !errors.As(err, &verifyErr) {
		t.Errorf("Expected VerificationError, got %T", err)
	}
}

func TestIntegration_WithRemoteIP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(DummySiteKeyAlwaysPass, DummySecretKeyAlwaysPass)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	valid, err := client.VerifyToken(context.Background(), DummyToken, "192.168.1.1")
	if err != nil {
		t.Fatalf("VerifyToken with remote IP failed: %v", err)
	}

	if !valid {
		t.Error("Expected token to be valid with remote IP")
	}
}
