package itsdangerous

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestSignVerifyStringRound(t *testing.T) {
	clock := &fakeClock{timestamp: 1234}
	s := NewSigner("foobarbimbaz", "application")
	s.WithClock(clock)

	payloads := []string{"hello", "foobar", "something else"}

	for _, p := range payloads {
		t.Run(fmt.Sprintf("can do a roundtrip signature for: %s", p),
			func(t *testing.T) {
				signed := s.SignString(p)
				decoded, timestamp, err := s.VerifyString(signed)

				if err != nil {
					t.Fatalf("roundtrip failed for payload %s: %v", p, err)

				}

				if timestamp != 1234 {
					t.Fatalf("invalid timestamp found in signature: %d", timestamp)
				}

				if decoded != p {
					t.Fatalf("could not find original payload in signed string: %s vs. %s", decoded, p)
				}
			})
	}
}

func TestSignVerifyStringRoundWithOldKeys(t *testing.T) {
	clock := &fakeClock{timestamp: 1234}
	s1 := NewSigner("foobarbimbaz", "application").WithClock(clock)

	s2 := NewSigner("helloiamadifferentkey", "application").WithClock(clock).WithExtraKey("foobarbimbaz")

	payloads := []string{"hello", "foobar", "something else"}

	for _, p := range payloads {
		t.Run(fmt.Sprintf("can do a roundtrip signature for: %s", p),
			func(t *testing.T) {
				signed := s1.SignString(p)
				decoded, timestamp, err := s2.VerifyString(signed)

				if err != nil {
					t.Fatalf("roundtrip failed for payload %s: %v", p, err)

				}

				if timestamp != 1234 {
					t.Fatalf("invalid timestamp found in signature: %d", timestamp)
				}

				if decoded != p {
					t.Fatalf("could not find original payload in signed string: %s vs. %s", decoded, p)
				}
			})
	}
}

func TestSignVerifyRound(t *testing.T) {
	clock := &fakeClock{timestamp: 1234}
	s := NewSigner("foobarbimbaz", "application")
	s.WithClock(clock)

	payloads := []Payload{
		{Identifier: "root", Expiry: "1s", Role: "admin"},
		{Identifier: "u1", Expiry: "1s", Role: "user"},
	}

	for _, p := range payloads {
		t.Run(fmt.Sprintf("can do a roundtrip signature on behalf of: %s", p.Identifier),
			func(t *testing.T) {
				signed, err := s.Sign(p)
				if err != nil {
					t.Fatalf("could not sign: %v", err)

				}
				decoded, err := s.Verify(signed)
				if err != nil {
					t.Fatalf("could not verify: %v", err)
				}

				if !reflect.DeepEqual(decoded, &p) {
					t.Fatalf("payload contents have changed")
				}
			})
	}
}

func TestVerifyExpiryRound(t *testing.T) {
	clock := &fakeClock{timestamp: 1234}
	s := NewSigner("foobarbimbaz", "application")
	s.WithClock(clock)

	payloads := []Payload{
		{Identifier: "root", Expiry: "1s", Role: "admin"},
		{Identifier: "u1", Expiry: "1s", Role: "user"},
	}

	for _, p := range payloads {
		t.Run(fmt.Sprintf("roundtrip with expiry is honored on behalf of: %s", p.Identifier),
			func(t *testing.T) {
				signed, err := s.Sign(p)
				if err != nil {
					t.Fatalf("could not sign: %v", err)

				}
				clock.shiftEpoch(5)
				decoded, err := s.Verify(signed)
				if !errors.Is(err, SignatureExpiredError) {
					t.Fatalf("verification should have failed due to expiry")
				}

				if !reflect.DeepEqual(decoded, &p) {
					t.Fatalf("payload contents have changed")
				}
			})
	}
}
