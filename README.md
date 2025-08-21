# go-itsdangerous

A Go implementation of the ItsDangerous signed token library, compatible with Python's [itsdangerous](https://itsdangerous.palletsprojects.com/en/stable/) library.

## Overview

This package provides cryptographically signed tokens for securely transmitting data. It uses HMAC-based signatures to ensure data integrity and authenticity, making it ideal for session cookies, API tokens, and other use cases where you need to verify that data hasn't been tampered with.

**Important**: This library provides data integrity and authenticity, but does not encrypt data. Never store confidential information in signed payloads as they can be read by anyone.

## Features

- HMAC-based token signing and verification
- Support for token expiration
- Key rotation support (multiple verification keys)
- Configurable salt for namespacing
- Pluggable hash algorithms (SHA-512 by default)
- Compatible with Python's itsdangerous library

## Installation

```bash
go get github.com/pyr/go-itsdangerous
```

## Usage

### Basic String Signing

```go
package main

import (
    "fmt"
    "github.com/pyr/go-itsdangerous"
)

func main() {
    // Create a signer with a secret key and salt
    signer := itsdangerous.NewSigner("your-secret-key", "your-app-name")
    
    // Sign a string
    signed := signer.SignString("hello world")
    fmt.Println("Signed:", signed)
    
    // Verify the signed string
    payload, timestamp, err := signer.VerifyString(signed)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("Payload:", payload)
    fmt.Println("Timestamp:", timestamp)
}
```

### Structured Payload Signing

```go
// Create a payload with expiration
payload := itsdangerous.Payload{
    Identifier: "user123",
    Role:       "admin",
    Expiry:     "1h", // Expires in 1 hour
    Data: map[string]string{
        "session_id": "abc123",
    },
}

// Sign the payload
signed, err := signer.Sign(payload)
if err != nil {
    panic(err)
}

// Verify and decode the payload
decoded, err := signer.Verify(signed)
if err != nil {
    panic(err)
}

fmt.Printf("User: %s, Role: %s\n", decoded.Identifier, decoded.Role)
```

### Key Rotation

```go
// Create signer with primary key
signer := itsdangerous.NewSigner("new-secret-key", "app-name")

// Add old keys for verification (allows gradual key rotation)
signer = signer.WithExtraKey("old-secret-key-1", "old-secret-key-2")

// Tokens signed with any of these keys will be valid for verification
// New tokens will be signed with the primary key only
```

### Custom Configuration

```go
import "crypto/sha256"

signer := itsdangerous.NewSigner("secret", "salt").
    WithHasher(sha256.New).  // Use SHA-256 instead of SHA-512
    WithSalt("custom-namespace")
```

## API Reference

### Signer

- `NewSigner(primaryKey, salt string) *Signer` - Create a new signer
- `SignString(payload string) string` - Sign a string
- `VerifyString(signed string) (string, int64, error)` - Verify a signed string
- `Sign(payload Payload) (string, error)` - Sign a structured payload
- `Verify(signed string) (*Payload, error)` - Verify and decode a structured payload

### Configuration Methods

- `WithExtraKey(keys ...string) *Signer` - Add additional verification keys
- `WithSalt(salt string) *Signer` - Set custom salt
- `WithHasher(hasher func() hash.Hash) *Signer` - Set custom hash algorithm
- `WithClock(clock Clock) *Signer` - Set custom clock (mainly for testing)

### Payload Structure

```go
type Payload struct {
    Expiry     string            `json:"expiry,omitempty"`     // Duration string (e.g., "1h", "30m")
    Identifier string            `json:"identifier,omitempty"` // User/entity identifier
    Role       string            `json:"role,omitempty"`       // Role or permission level
    Data       map[string]string `json:"data,omitempty"`       // Additional key-value data
}
```

## Security Considerations

1. **Keep secret keys secure** - Store them in environment variables or secure configuration
2. **Use strong, random keys** - Generate cryptographically secure random keys
3. **Rotate keys regularly** - Use the key rotation feature to gradually replace old keys
4. **Don't store secrets in payloads** - Signed data is not encrypted and can be read by anyone
5. **Use appropriate expiration times** - Set reasonable expiry durations for your use case

## Testing

```bash
go test
```

## License

This project follows the same principles as Python's itsdangerous library for cross-platform compatibility.