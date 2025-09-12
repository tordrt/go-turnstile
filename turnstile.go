package turnstile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

const (
	verifyEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	timeout        = 10 * time.Second
)

// Client handles verification of Turnstile tokens
type Client struct {
	LoginSiteKey string
	secretKey    string
	client       *http.Client
}

func NewTurnstileClient(loginSiteKey, secretKey string) *Client {
	return &Client{
		LoginSiteKey: loginSiteKey,
		secretKey:    secretKey,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (s *Client) Verify(ctx context.Context, tsResponse string) (bool, error) {
	if strings.TrimSpace(tsResponse) == "" {
		return false, errors.New("turnstile response token cannot be empty")
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if err := writer.WriteField("secret", s.secretKey); err != nil {
		return false, fmt.Errorf("failed to write secret field: %w", err)
	}
	if err := writer.WriteField("response", tsResponse); err != nil {
		return false, fmt.Errorf("failed to write response field: %w", err)
	}
	//_ = writer.WriteField("remoteip", ip) Maybe add in future
	if err := writer.Close(); err != nil {
		return false, fmt.Errorf("failed to close multipart writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", verifyEndpoint, body)
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	result, err := s.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("request failed: %w", err)
	}
	defer result.Body.Close()

	var outcome map[string]any
	if err := json.NewDecoder(result.Body).Decode(&outcome); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	success, ok := outcome["success"].(bool)
	if !ok {
		return false, errors.New("invalid response format: missing success field")
	}

	if !success {
		if errorCodes, exists := outcome["error-codes"]; exists {
			return false, fmt.Errorf("turnstile verification failed: %v", errorCodes)
		}
		return false, errors.New("turnstile verification failed")
	}

	return true, nil
}
