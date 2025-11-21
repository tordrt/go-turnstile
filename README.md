# go-turnstile

[![Go Version](https://img.shields.io/github/go-mod/go-version/tordrt/go-turnstile)](go.mod)
[![Go Reference](https://pkg.go.dev/badge/github.com/tordrt/go-turnstile.svg)](https://pkg.go.dev/github.com/tordrt/go-turnstile)
[![Go Report Card](https://goreportcard.com/badge/github.com/tordrt/go-turnstile)](https://goreportcard.com/report/github.com/tordrt/go-turnstile)
[![License](https://img.shields.io/github/license/tordrt/go-turnstile)](LICENSE)

A simple, thread-safe Go client library for verifying Cloudflare Turnstile CAPTCHA tokens.

Cloudflare Turnstile is an alternative to traditional CAPTCHAs that helps websites protect against bots and automated traffic while providing a better user experience. This library provides a clean, idiomatic Go interface for server-side token verification.

## Features

- ✅ **Thread-safe**: Safe for concurrent use by multiple goroutines
- ✅ **Automatic retries**: Built-in retry logic for transient network failures
- ✅ **Idempotency protection**: Automatic unique idempotency keys prevent replay attacks
- ✅ **Structured error handling**: Specific error types for different failure scenarios
- ✅ **Flexible configuration**: Customizable timeouts, endpoints, and HTTP clients
- ✅ **Request helpers**: Easy extraction of tokens from HTTP requests
- ✅ **Zero dependencies**: Only uses Go standard library (except for UUID generation)

## Installation

```bash
go get github.com/tordrt/go-turnstile
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    "net/http"
    
    "github.com/tordrt/go-turnstile"
)

func main() {
    // Create a new Turnstile client
	turnstileClient, err := turnstile.New("your-site-key", "your-secret-key")
    if err != nil {
        log.Fatal(err)
    }

    http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
        // Verify the token from the HTTP request
        response, err := turnstileClient.VerifyRequest(r.Context(), r)
        if err != nil {
            http.Error(w, "CAPTCHA verification failed", http.StatusBadRequest)
            return
        }
        
        fmt.Fprintf(w, "Verification successful! Hostname: %s", response.Hostname)
    })
    
    log.Println("Server starting on :8080")
    http.ListenAndServe(":8080", nil)
}
```

## Usage Examples

### Basic Token Verification

```go
// Verify a token directly
response, err := turnstileClient.VerifyToken(context.TODO(), clientToken, clientIP)
if err != nil {
    // Handle verification error
    return
}
// Verification successful
```

### HTTP Request Verification

The `VerifyRequest` method automatically extracts the token from the `cf-turnstile-response` form field and determines the client IP:

```go
func handlerFunction(w http.ResponseWriter, r *http.Request) {
    response, err := turnstileClient.VerifyRequest(r.Context(), r)
    if err != nil {
        // Handle verification failure
        return
    }
    
    // Verification successful
}
```

### Advanced Configuration

```go
turnstileClient, err := turnstile.New(
    "your-site-key",
    "your-secret-key",
    turnstile.WithMaxRetries(3),
    turnstile.WithRetryDelay(200*time.Millisecond),
    turnstile.WithHTTPClient(&http.Client{
        Timeout: 5 * time.Second,
        Transport: &http.Transport{
            MaxIdleConns: 10,
        },
    }),
)
```

### Error Handling

The library provides specific error types for different failure scenarios:

```go
response, err := turnstileClient.VerifyToken(r.Context(), token, clientIP)
if err != nil {
    // Check for specific error types
    var timeoutErr turnstile.ErrTimeoutOrDuplicate
    if errors.As(err, &timeoutErr) {
        log.Println("Token timeout or duplicate submission:", err)
        return
    }

    var invalidTokenErr turnstile.ErrInvalidInputResponse
    if errors.As(err, &invalidTokenErr) {
        log.Println("Invalid token provided:", err)
        return
    }

    // Handle other verification errors
    log.Println("Verification failed:", err)
    return
}
```

## Configuration Options

### Client Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithHTTPClient(client)` | Custom HTTP client | 3 second timeout |
| `WithVerifyEndpoint(url)` | Custom verification endpoint | Cloudflare's official endpoint |
| `WithMaxRetries(n)` | Maximum retry attempts | 2 |
| `WithRetryDelay(duration)` | Initial retry delay (exponential backoff) | 100ms |

### Default Values

```go
const (
    DefaultVerifyEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    DefaultTimeout        = 3 * time.Second
    DefaultMaxRetries     = 2
    DefaultRetryDelay     = 100 * time.Millisecond
)
```

## Error Types

The library provides structured error handling with specific error types:

- `ErrInvalidSiteKey`: Site key is empty or invalid
- `ErrInvalidSecretKey`: Secret key is empty or invalid  
- `ErrEmptyToken`: Token is empty or whitespace
- `ErrMissingInputSecret`: Secret key missing in request
- `ErrInvalidInputSecret`: Secret key is invalid
- `ErrMissingInputResponse`: Token missing in request
- `ErrInvalidInputResponse`: Token is invalid or expired
- `ErrBadRequest`: Malformed request
- `ErrTimeoutOrDuplicate`: Token timeout or duplicate submission
- `ErrInternalError`: Cloudflare internal error

## Response Structure

The `Response` struct contains the complete verification result:

```go
type Response struct {
    Success     bool              `json:"success"`
    ChallengeTS string            `json:"challenge_ts,omitempty"`
    Hostname    string            `json:"hostname,omitempty"`
    ErrorCodes  []string          `json:"error-codes,omitempty"`
    Action      string            `json:"action,omitempty"`
    CData       string            `json:"cdata,omitempty"`
    Metadata    *ResponseMetadata `json:"metadata,omitempty"` // Enterprise only
}
```

## HTML Integration

Here's a complete HTML form example:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Turnstile Demo</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body>
    <form action="/verify" method="POST">
        <div class="cf-turnstile" data-sitekey="your-site-key"></div>
        <input type="submit" value="Submit">
    </form>
</body>
</html>
```

## Testing

This library provides convenient test helpers that make it easy to test your Turnstile integration without setting up real Cloudflare keys or widgets. The test clients use [Cloudflare's official dummy keys](https://developers.cloudflare.com/turnstile/reference/testing/) under the hood.

### Quick Start - Testing

```go
import (
    "testing"
    "context"
    "github.com/tordrt/go-turnstile"
)

func TestMyHandler(t *testing.T) {
    // Create a test client that always passes verification
    client := turnstile.NewTestClient()

    // Use the test token to verify
    response, err := client.VerifyToken(context.Background(), turnstile.TestToken)
    if err != nil {
        t.Fatalf("Expected successful verification: %v", err)
    }

    // Test your handler logic with a valid token
    if !response.Success {
        t.Error("Expected successful response")
    }
}
```

### Test Client Types

The library provides three test client constructors for different testing scenarios:

#### 1. NewTestClient() - Success Case Testing
Creates a client that always passes verification. Use this to test your happy path logic.

```go
func TestHandlerSuccess(t *testing.T) {
    client := turnstile.NewTestClient()
    response, err := client.VerifyToken(context.Background(), turnstile.TestToken)
    // err will be nil, response.Success will be true
}
```

#### 2. NewTestClientAlwaysFail() - Failure Case Testing
Creates a client that always fails verification. Use this to test your error handling.

```go
func TestHandlerFailure(t *testing.T) {
    client := turnstile.NewTestClientAlwaysFail()
    _, err := client.VerifyToken(context.Background(), turnstile.TestToken)
    // err will not be nil - test your error handling here
    if err == nil {
        t.Fatal("Expected verification to fail")
    }
}
```

#### 3. NewTestClientTokenSpent() - Duplicate Token Testing
Creates a client that returns a "token already spent" error. Use this to test replay attack protection.

```go
func TestHandlerDuplicateToken(t *testing.T) {
    client := turnstile.NewTestClientTokenSpent()
    _, err := client.VerifyToken(context.Background(), turnstile.TestToken)

    var timeoutErr turnstile.ErrTimeoutOrDuplicate
    if !errors.As(err, &timeoutErr) {
        t.Fatal("Expected timeout-or-duplicate error")
    }
    // Test your duplicate submission handling
}
```

### Test Constants

The library exports the following test constants for use in your tests:

| Constant | Description |
|----------|-------------|
| `turnstile.TestToken` | Dummy response token accepted by all test clients |
| `turnstile.TestSiteKeyAlwaysPass` | Dummy sitekey that always passes (visible) |
| `turnstile.TestSiteKeyAlwaysBlock` | Dummy sitekey that always blocks (visible) |
| `turnstile.TestSiteKeyAlwaysPassInvisible` | Dummy sitekey that always passes (invisible) |
| `turnstile.TestSiteKeyAlwaysBlockInvisible` | Dummy sitekey that always blocks (invisible) |
| `turnstile.TestSiteKeyForceChallenge` | Dummy sitekey that forces interactive challenge |
| `turnstile.TestSecretKeyAlwaysPass` | Dummy secret key that always passes |
| `turnstile.TestSecretKeyAlwaysFail` | Dummy secret key that always fails |
| `turnstile.TestSecretKeyTokenSpent` | Dummy secret key that returns "token spent" error |

### Complete Test Example

```go
func TestTurnstileHandler(t *testing.T) {
    tests := []struct {
        name        string
        client      *turnstile.Client
        expectError bool
    }{
        {
            name:        "successful verification",
            client:      turnstile.NewTestClient(),
            expectError: false,
        },
        {
            name:        "failed verification",
            client:      turnstile.NewTestClientAlwaysFail(),
            expectError: true,
        },
        {
            name:        "duplicate token",
            client:      turnstile.NewTestClientTokenSpent(),
            expectError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            response, err := tt.client.VerifyToken(
                context.Background(),
                turnstile.TestToken,
            )

            if tt.expectError && err == nil {
                t.Error("Expected error but got none")
            }
            if !tt.expectError && err != nil {
                t.Errorf("Unexpected error: %v", err)
            }
        })
    }
}
```

For more examples, see the [example_test.go](example_test.go) file.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Related

- [Cloudflare Turnstile Documentation](https://developers.cloudflare.com/turnstile/)
- [Turnstile API Reference](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
