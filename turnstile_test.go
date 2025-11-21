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

// Test constants are now exported in testing.go for public use
// This file uses those exported constants for internal testing

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		siteKey   string
		secretKey string
		wantErr   bool
	}{
		{
			name:      "valid keys with dummy always-pass",
			siteKey:   TestSiteKeyAlwaysPass,
			secretKey: TestSecretKeyAlwaysPass,
			wantErr:   false,
		},
		{
			name:      "empty site key",
			siteKey:   "",
			secretKey: TestSecretKeyAlwaysPass,
			wantErr:   true,
		},
		{
			name:      "empty secret key",
			siteKey:   TestSiteKeyAlwaysPass,
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
		client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass,
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
		customClient := &http.Client{Timeout: customTimeout}
		client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass,
			WithHTTPClient(customClient),
		)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		if client.client.Timeout != customTimeout {
			t.Errorf("WithHTTPClient() timeout got %v, want %v", client.client.Timeout, customTimeout)
		}
	})

	t.Run("WithVerifyEndpoint", func(t *testing.T) {
		customEndpoint := "https://custom.example.com/verify"
		client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass,
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
		customTimeout := 15 * time.Second
		customClient := &http.Client{Timeout: customTimeout}
		customEndpoint := "https://custom.example.com/verify"

		client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass,
			WithHTTPClient(customClient),
			WithVerifyEndpoint(customEndpoint),
		)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		if client.client != customClient {
			t.Error("WithHTTPClient() did not set custom HTTP client")
		}
		if client.client.Timeout != customTimeout {
			t.Errorf("WithHTTPClient() timeout got %v, want %v", client.client.Timeout, customTimeout)
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
			token:          TestToken,
			responseStatus: 200,
			responseBody:   `{"success": true}`,
			wantValid:      true,
			wantErr:        false,
		},
		{
			name:           "invalid token with always-fail dummy secret",
			token:          TestToken,
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
			token:          TestToken,
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
				if _, err := w.Write([]byte(tt.responseBody)); err != nil {
					t.Errorf("Failed to write response: %v", err)
				}
			}))
			defer server.Close()

			client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass,
				WithVerifyEndpoint(server.URL),
			)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			response, err := client.VerifyToken(context.Background(), tt.token, tt.remoteIP)

			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			valid := response != nil && response.Success
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
						// Check if it's one of the specific error types that embed VerificationError
						switch err.(type) {
						case *ErrInvalidInputSecret, *ErrInvalidInputResponse, *ErrTimeoutOrDuplicate,
							*ErrMissingInputSecret, *ErrMissingInputResponse, *ErrBadRequest, *ErrInternalError:
							// This is expected - specific error types
						default:
							t.Errorf("Expected VerificationError or specific error type, got %T", err)
						}
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
				if _, err := w.Write([]byte(tt.responseBody)); err != nil {
					t.Errorf("Failed to write response: %v", err)
				}
			}))
			defer server.Close()

			client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass,
				WithVerifyEndpoint(server.URL),
			)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			_, err = client.VerifyToken(context.Background(), TestToken, "192.168.1.1")

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
		if _, err := w.Write([]byte(`{"success": true}`)); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	}))
	defer server.Close()

	client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass,
		WithVerifyEndpoint(server.URL),
	)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err = client.VerifyToken(ctx, TestToken, "192.168.1.1")
	if err == nil {
		t.Error("Expected context cancellation error, got nil")
	}
}

// TestIPExtraction tests the basic IP extraction from RemoteAddr
func TestIPExtraction(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "IPv4 RemoteAddr",
			remoteAddr: "203.0.113.3:54321",
			expectedIP: "203.0.113.3",
		},
		{
			name:       "IPv6 RemoteAddr",
			remoteAddr: "[2001:db8::1]:54321",
			expectedIP: "[2001:db8::1]",
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
				if _, err := w.Write([]byte(`{"success": true}`)); err != nil {
					t.Errorf("Failed to write response: %v", err)
				}
			}))
			defer server.Close()

			client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass,
				WithVerifyEndpoint(server.URL),
			)
			if err != nil {
				t.Fatalf("New() failed: %v", err)
			}

			// Create request with turnstile token
			formData := strings.NewReader("cf-turnstile-response=" + TestToken)
			req := httptest.NewRequest(http.MethodPost, "/test", formData)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = tt.remoteAddr

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
				"cf-turnstile-response": TestToken,
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
				"cf-turnstile-response": TestToken,
				"username":              "test",
				"email":                 "test@example.com",
			},
			responseStatus: 200,
			responseBody:   `{"success": true}`,
			wantValid:      true,
			wantErr:        false,
		},
		{
			name: "request with RemoteAddr",
			formData: map[string]string{
				"cf-turnstile-response": TestToken,
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
				if _, err := w.Write([]byte(tt.responseBody)); err != nil {
					t.Errorf("Failed to write response: %v", err)
				}
			}))
			defer server.Close()

			client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass,
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

			response, err := client.VerifyRequest(context.Background(), req)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			valid := response != nil && response.Success
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

	client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	response, err := client.VerifyToken(context.Background(), TestToken, "")
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}

	if response == nil || !response.Success {
		t.Error("Expected token to be valid with always-pass test key")
	}
}

func TestIntegration_AlwaysFail(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(TestSiteKeyAlwaysBlock, TestSecretKeyAlwaysFail)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	response, err := client.VerifyToken(context.Background(), TestToken, "")
	if err == nil {
		t.Fatal("Expected error for always-fail secret key")
	}

	if response != nil && response.Success {
		t.Error("Expected token to be invalid with always-fail secret key")
	}

	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) {
		// Check if it's one of the specific error types that embed VerificationError
		switch err.(type) {
		case *ErrInvalidInputSecret, *ErrInvalidInputResponse, *ErrTimeoutOrDuplicate,
			*ErrMissingInputSecret, *ErrMissingInputResponse, *ErrBadRequest, *ErrInternalError:
			// This is expected - specific error types
		default:
			t.Errorf("Expected VerificationError or specific error type, got %T", err)
		}
	}
}

func TestIntegration_TokenAlreadySpent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyTokenSpent)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	response, err := client.VerifyToken(context.Background(), TestToken, "")
	if err == nil {
		t.Fatal("Expected 'token already spent' error")
	}

	if response != nil && response.Success {
		t.Error("Expected token to be invalid for 'token already spent' scenario")
	}

	var verificationErr *VerificationError
	if !errors.As(err, &verificationErr) {
		// Check if it's one of the specific error types that embed VerificationError
		switch err.(type) {
		case *ErrInvalidInputSecret, *ErrInvalidInputResponse, *ErrTimeoutOrDuplicate,
			*ErrMissingInputSecret, *ErrMissingInputResponse, *ErrBadRequest, *ErrInternalError:
			// This is expected - specific error types
		default:
			t.Errorf("Expected VerificationError or specific error type, got %T", err)
		}
	}
}

func TestIntegration_WithRemoteIP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client, err := New(TestSiteKeyAlwaysPass, TestSecretKeyAlwaysPass)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	response, err := client.VerifyToken(context.Background(), TestToken, "192.168.1.1")
	if err != nil {
		t.Fatalf("VerifyToken with remote IP failed: %v", err)
	}

	if response == nil || !response.Success {
		t.Error("Expected token to be valid with remote IP")
	}
}
