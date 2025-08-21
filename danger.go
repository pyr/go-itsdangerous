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

// To help with testing, the clock used in testing can be replaced
type Clock interface {
	Epoch() int64
}

// The signer type hold configuration for a particular signer/verifier
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

type Payload struct {
	Expiry     string            `json:"expiry,omitempty"`
	Identifier string            `json:"identifier,omitempty"`
	Role       string            `json:"role,omitempty"`
	Data       map[string]string `json:"data,omitempty"`
}

// Default clock used to produce timestamps
var WallClock = wallClock{}

func (_ wallClock) Epoch() int64 {
	return time.Now().Unix()
}

func (fake *fakeClock) Epoch() int64 {
	return fake.timestamp
}

func (fake *fakeClock) setEpoch(timestamp int64) {
	fake.timestamp = timestamp
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
			return &p, fmt.Errorf("payload signature has expired")
		}
	}
	return &p, nil
}

// Yield a signed string for a particular input. The resulting
// signed string will contain 3 parts: the encoded payload, timestamp,
// and signature
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

// Validates the signature of a signed string
// Yields a tuple of (decoded-payload, timestamp, error)
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

func NewSigner(primaryKey string, salt string) *Signer {
	return &Signer{
		keys:   []string{primaryKey},
		salt:   salt,
		clock:  WallClock,
		hasher: sha512.New,
	}
}

func (s *Signer) WithClock(clock Clock) *Signer {
	s.clock = clock
	return s
}

func (s *Signer) WithExtraKey(keys ...string) *Signer {
	return s.WithExtraKeys(keys)
}

func (s *Signer) WithExtraKeys(keys []string) *Signer {
	for _, k := range keys {
		s.keys = append(s.keys, k)
	}
	return s
}

func (s *Signer) WithSalt(salt string) *Signer {
	s.salt = salt
	return s
}

func (s *Signer) WithHasher(hasher func() hash.Hash) *Signer {
	s.hasher = hasher
	return s
}
