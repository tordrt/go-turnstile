# go-turnstile

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
    "context"
    "fmt"
    "log"
    "net/http"
    
    "github.com/tordrt/go-turnstile"
)

func main() {
    // Create a new Turnstile client
    client, err := turnstile.New("your-site-key", "your-secret-key")
    if err != nil {
        log.Fatal(err)
    }

    http.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
        // Verify the token from the HTTP request
        response, err := client.VerifyRequest(context.Background(), r)
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
client, err := turnstile.New("your-site-key", "your-secret-key")
if err != nil {
    // Handle client creation error
    return
}

// Verify a token directly
response, err := client.VerifyToken(context.Background(), "user-token", "192.168.1.1")
if err != nil {
    // Handle verification error
    return
}

// Access response fields
fmt.Printf("Challenge completed at: %s\n", response.ChallengeTS)
fmt.Printf("Hostname: %s\n", response.Hostname)
fmt.Printf("Action: %s\n", response.Action)
```

### HTTP Request Verification

The `VerifyRequest` method automatically extracts the token from the `cf-turnstile-response` form field and determines the client IP:

```go
func handleForm(w http.ResponseWriter, r *http.Request) {
    response, err := client.VerifyRequest(context.Background(), r)
    if err != nil {
        // Handle verification failure
        http.Error(w, "CAPTCHA verification failed", http.StatusBadRequest)
        return
    }
    
    // Verification successful - proceed with form processing
    processForm(r)
}
```

### Advanced Configuration

```go
client, err := turnstile.New(
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
response, err := client.VerifyToken(context.Background(), token, clientIP)
if err != nil {
    // Check for specific error types
    var timeoutErr *turnstile.ErrTimeoutOrDuplicate
    if errors.As(err, &timeoutErr) {
        log.Println("Token timeout or duplicate submission:", err)
        return
    }
    
    var invalidTokenErr *turnstile.ErrInvalidInputResponse
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

Cloudflare provides dummy site keys and secret keys for testing and development. These keys allow you to test your integration without setting up a real Turnstile widget.

For the complete list of test keys and their behaviors, see: [Cloudflare Turnstile Test Keys](https://developers.cloudflare.com/turnstile/reference/testing/)

### Example Test Usage

```go
func TestTurnstileVerification(t *testing.T) {
    // Use Cloudflare's dummy keys for testing
    // See: https://developers.cloudflare.com/turnstile/reference/testing/
    client, err := turnstile.New("test-site-key", "test-secret-key")
    assert.NoError(t, err)
    
    response, err := client.VerifyToken(context.Background(), "dummy-token", "127.0.0.1")
    // Result depends on which test keys you use
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Related

- [Cloudflare Turnstile Documentation](https://developers.cloudflare.com/turnstile/)
- [Turnstile API Reference](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
