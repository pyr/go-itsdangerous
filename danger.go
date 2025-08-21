// ItsDangerous signed token implementation.
// This package provides a new type Signer which offers both `SignString` and `VerifyString`
//
// Signer hold configuration for token signing and verifying. This follows
// the scheme documented here: https://itsdangerous.palletsprojects.com/en/stable/
//
// ItsDangerous uses a simple hmac-based scheme to sign arbitrary strings, in the
// Python world, this scheme is often used to sign cookies. Note that ItsDangerous
// provides no concrete way to hide data from onlookers, but simply to sign
// payloads, it is thus important never to store confidential data in the
// signed payload.
//
// ItsDangerous relies on knowledge that needs to be shared out-of-band between
// signers and verifiers:
//
// - A secret key for signing
// - A set of acceptable secret keys for verifying, allowing for rolling keys
// - A somewhat badly named salt, used for namespacing
// - A hashing algorithm, SHA-512 is used by default
//
// To simplify the classical use of using this for cookie signing of sessions,
// A `Sign` and `Verify` signatures are provided which operate on a payload
// structure supporting expiry. the Expiry is expressed as a valid go duration
// expression.
package itsdangerous

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
	"time"
)

// Clock provides an interface for obtaining the current time as a Unix timestamp.
// This abstraction allows for deterministic testing by injecting a fake clock.
type Clock interface {
	// Epoch returns the current time as a Unix timestamp (seconds since January 1, 1970 UTC).
	Epoch() int64
}

// Signer holds configuration for token signing and verification operations.
// It contains the cryptographic keys, salt for namespacing, clock for timestamps,
// and hash function used for HMAC operations.
type Signer struct {
	keys   []string
	salt   string
	clock  Clock
	hasher func() hash.Hash
}

type wallClock struct{}

type fakeClock struct {
	timestamp int64
}

// Payload represents a structured data container that can be signed and verified.
// It supports expiration times, user identification, role-based access, and arbitrary data.
type Payload struct {
	// Expiry specifies when the payload expires as a Go duration string (e.g., "1h", "30m", "24h").
	// If empty, the payload never expires.
	Expiry string `json:"expiry,omitempty"`

	// Identifier is typically used to store a user ID or entity identifier.
	Identifier string `json:"identifier,omitempty"`

	// Role represents the permission level or role associated with this payload.
	Role string `json:"role,omitempty"`

	// Data contains arbitrary key-value pairs for additional payload information.
	Data map[string]string `json:"data,omitempty"`
}

// WallClock is the default clock implementation that returns the current system time.
// It is used by default when creating new Signer instances.
var WallClock = wallClock{}

// SignatureExpiredError is returned when a payload expiry has been reached at verification time.
var SignatureExpiredError = fmt.Errorf("payload signature has expired")

func (wallClock) Epoch() int64 {
	return time.Now().Unix()
}

func (fake *fakeClock) Epoch() int64 {
	return fake.timestamp
}

func (fake *fakeClock) shiftEpoch(delta int64) {
	fake.timestamp += delta
}

func (s *Signer) primaryKey() string {
	return s.keys[0]
}

func (s *Signer) stringToSign(payload string) string {
	clockBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(clockBytes, uint64(s.clock.Epoch()))

	return fmt.Sprintf("%s.%s",
		base64.URLEncoding.EncodeToString([]byte(payload)),
		base64.URLEncoding.EncodeToString([]byte(clockBytes)))
}

func (s *Signer) createKeyMac(key string) hash.Hash {
	mac := hmac.New(s.hasher, []byte(key))
	derivedKey := mac.Sum([]byte(s.salt))
	derivedMac := hmac.New(s.hasher, derivedKey)
	return derivedMac
}

func (s *Signer) createSignature(input []byte) string {

	mac := s.createKeyMac(s.primaryKey())
	output := mac.Sum([]byte(input))
	return base64.URLEncoding.EncodeToString(output)
}

// Sign creates a cryptographically signed token from a structured Payload.
// The payload is JSON-encoded and then signed using the signer's primary key.
// If the payload contains an Expiry field, it must be a valid Go duration string.
//
// Returns the signed token string or an error if the payload cannot be marshaled
// or contains an invalid expiry duration.
func (s *Signer) Sign(payload Payload) (string, error) {
	// Avoid late errors due to invalid durations
	if payload.Expiry != "" {
		_, err := time.ParseDuration(payload.Expiry)
		if err != nil {
			return "", err
		}
	}
	bs, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return s.SignString(string(bs)), nil
}

// Verify validates a signed token and returns the decoded Payload.
// It first verifies the cryptographic signature using any of the configured keys,
// then checks if the payload has expired based on its Expiry field and signing timestamp.
//
// Returns the decoded payload or an error if the signature is invalid,
// the payload is malformed, or the token has expired.
func (s *Signer) Verify(signedString string) (*Payload, error) {
	decoded, timestamp, err := s.VerifyString(signedString)
	if err != nil {
		return nil, err
	}
	var p Payload
	err = json.Unmarshal([]byte(decoded), &p)
	if err != nil {
		return nil, err
	}
	if p.Expiry != "" {
		tm := time.Unix(timestamp, 0)
		now := time.Unix(s.clock.Epoch(), 0)
		duration, err := time.ParseDuration(p.Expiry)
		if err != nil {
			return &p, err
		}
		if tm.Add(duration).Before(now) {
			return &p, SignatureExpiredError
		}
	}
	return &p, nil
}

// SignString creates a cryptographically signed token from a raw string payload.
// The resulting signed string contains three dot-separated parts:
// 1. Base64-encoded payload
// 2. Base64-encoded timestamp
// 3. Base64-encoded HMAC signature
//
// This is the low-level signing method used by Sign().
func (s *Signer) SignString(payload string) string {
	input := s.stringToSign(payload)
	sig := s.createSignature([]byte(input))
	return fmt.Sprintf("%s.%s", input, sig)
}

func (s *Signer) verifySignature(stringToSign string, signature string) error {
	decodedSig, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	for _, k := range s.keys {
		mac := s.createKeyMac(k)
		output := mac.Sum([]byte(stringToSign))
		if hmac.Equal(decodedSig, output) {
			return nil
		}
	}
	return fmt.Errorf("no key permitted to validate signature")
}

// VerifyString validates the cryptographic signature of a signed token and extracts its contents.
// It parses the three-part token format, decodes the payload and timestamp,
// and verifies the signature against all configured keys.
//
// Returns the decoded payload string, the signing timestamp as Unix seconds,
// and an error if the token format is invalid or signature verification fails.
func (s *Signer) VerifyString(input string) (string, int64, error) {

	parts := strings.SplitN(input, ".", 3)
	if len(parts) != 3 {
		return "", 0, fmt.Errorf("invalid payload format")
	}
	payload, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}
	clockBytes, err := base64.URLEncoding.DecodeString(parts[1])
	if err != nil {
		return string(payload), 0, err
	}
	timestamp := int64(binary.LittleEndian.Uint64(clockBytes))

	err = s.verifySignature(strings.Join(parts[:2], "."), parts[2])
	return string(payload), timestamp, err

}

// NewSigner creates a new Signer instance with the specified primary key and salt.
// The signer is configured with default settings:
// - Uses the provided primaryKey for signing (additional keys can be added for verification)
// - Uses the provided salt for key derivation and namespacing
// - Uses WallClock for timestamps
// - Uses SHA-512 as the hash algorithm
//
// The salt should be unique per application to prevent signature reuse across different contexts.
func NewSigner(primaryKey string, salt string) *Signer {
	return &Signer{
		keys:   []string{primaryKey},
		salt:   salt,
		clock:  WallClock,
		hasher: sha512.New,
	}
}

// WithClock configures the signer to use a custom clock for timestamp generation.
// This is primarily useful for testing with deterministic timestamps.
// Returns the signer instance for method chaining.
func (s *Signer) WithClock(clock Clock) *Signer {
	s.clock = clock
	return s
}

// WithExtraKey adds additional keys that can be used for signature verification.
// This enables key rotation: new tokens are signed with the primary key,
// but tokens signed with any of the extra keys will still verify successfully.
// Returns the signer instance for method chaining.
func (s *Signer) WithExtraKey(keys ...string) *Signer {
	return s.WithExtraKeys(keys)
}

// WithExtraKeys adds a slice of additional keys that can be used for signature verification.
// This enables key rotation: new tokens are signed with the primary key,
// but tokens signed with any of the extra keys will still verify successfully.
// Returns the signer instance for method chaining.
func (s *Signer) WithExtraKeys(keys []string) *Signer {
	s.keys = append(s.keys, keys...)
	return s
}

// WithSalt configures the signer to use a custom salt for key derivation.
// The salt provides namespacing to prevent signature reuse across different applications
// or contexts. Changing the salt will invalidate all existing signatures.
// Returns the signer instance for method chaining.
func (s *Signer) WithSalt(salt string) *Signer {
	s.salt = salt
	return s
}

// WithHasher configures the signer to use a custom hash algorithm for HMAC operations.
// The default is SHA-512. Common alternatives include sha256.New for SHA-256.
// Changing the hasher will invalidate all existing signatures.
// Returns the signer instance for method chaining.
func (s *Signer) WithHasher(hasher func() hash.Hash) *Signer {
	s.hasher = hasher
	return s
}
