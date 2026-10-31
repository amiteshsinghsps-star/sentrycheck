package main

import (
	"crypto/ed25519"
	"sentrycheck.local/integration/internal/attest"
	"time"
)

func verifyOne(envelope attest.Envelope, id string, key ed25519.PublicKey, now time.Time, maxAge time.Duration) (attest.Claims, error) {
	return attest.Verify(envelope, map[string]ed25519.PublicKey{id: key}, now, maxAge)
}
