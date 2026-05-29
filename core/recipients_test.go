package core

import (
	"bytes"
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
)

func TestGenerateKeypair(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	// Verify public key is non-zero.
	zeros := [32]byte{}
	if bytes.Equal(pub[:], zeros[:]) {
		t.Error("public key is all zeros")
	}

	// Round-trip: public key must equal X25519(private, Basepoint).
	derived, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("X25519(priv, Basepoint): %v", err)
	}
	if !bytes.Equal(pub[:], derived) {
		t.Error("public key does not match derived public key from private key")
	}

	// Determinism: same private key produces same public key.
	derived2, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("second X25519: %v", err)
	}
	if !bytes.Equal(derived, derived2) {
		t.Error("public key derivation is not deterministic")
	}
}

func TestX25519WrapUnwrap(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	var fileKey [RecipientFileKeySize]byte
	if _, err := rand.Read(fileKey[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	recip := &X25519Recipient{PubKey: pub}
	stanza, err := recip.Wrap(fileKey[:])
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	if stanza.Type != RecipientTypeX25519 {
		t.Errorf("stanza type = %d, want %d", stanza.Type, RecipientTypeX25519)
	}

	ident := &X25519Identity{PrivKey: priv}
	unwrapped, err := ident.Unwrap([]RecipientStanza{stanza})
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}

	if !bytes.Equal(unwrapped, fileKey[:]) {
		t.Error("unwrapped file key does not match original")
	}
}

func TestX25519WrongIdentity(t *testing.T) {
	pubA, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair A: %v", err)
	}
	_, privB, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair B: %v", err)
	}

	var fileKey [RecipientFileKeySize]byte
	if _, err := rand.Read(fileKey[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	recip := &X25519Recipient{PubKey: pubA}
	stanza, err := recip.Wrap(fileKey[:])
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// A wrong identity decrypts successfully but produces a different key
	// (garbage) since the ECDH shared secret is different.
	ident := &X25519Identity{PrivKey: privB}
	unwrapped, err := ident.Unwrap([]RecipientStanza{stanza})
	if err != nil {
		t.Errorf("unexpected error for wrong identity: %v", err)
	}
	if bytes.Equal(unwrapped, fileKey[:]) {
		t.Error("wrong identity should not produce the original file key")
	}
}

func TestX25519NoMatchingStanzaType(t *testing.T) {
	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	var fileKey [RecipientFileKeySize]byte
	if _, err := rand.Read(fileKey[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	recip := &X25519Recipient{PubKey: pub}
	_, err = recip.Wrap(fileKey[:])
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	// Empty stanzas list should return ErrNoMatchingRecipient.
	ident := &X25519Identity{PrivKey: pub}
	_, err = ident.Unwrap(nil)
	if err != ErrNoMatchingRecipient {
		t.Errorf("expected ErrNoMatchingRecipient for nil stanzas, got %v", err)
	}

	// Stanza with wrong type should be skipped, resulting in ErrNoMatchingRecipient.
	wrongTypeStanza := RecipientStanza{Type: 0xDEADBEEF}
	_, err = ident.Unwrap([]RecipientStanza{wrongTypeStanza})
	if err != ErrNoMatchingRecipient {
		t.Errorf("expected ErrNoMatchingRecipient for wrong type, got %v", err)
	}
}

func TestX25519MultipleRecipients(t *testing.T) {
	const numRecipients = 3

	// Generate 3 keypairs.
	pubs := make([][32]byte, numRecipients)
	privs := make([][32]byte, numRecipients)
	for i := 0; i < numRecipients; i++ {
		pub, priv, err := GenerateKeypair()
		if err != nil {
			t.Fatalf("GenerateKeypair %d: %v", i, err)
		}
		pubs[i] = pub
		privs[i] = priv
	}

	// Use the same file key for all recipients.
	var fileKey [RecipientFileKeySize]byte
	if _, err := rand.Read(fileKey[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Wrap for all recipients.
	stanzas := make([]RecipientStanza, numRecipients)
	for i := 0; i < numRecipients; i++ {
		recip := &X25519Recipient{PubKey: pubs[i]}
		stanza, err := recip.Wrap(fileKey[:])
		if err != nil {
			t.Fatalf("Wrap %d: %v", i, err)
		}
		stanzas[i] = stanza
	}

	// Each identity can decrypt its own stanza.
	for i := 0; i < numRecipients; i++ {
		ident := &X25519Identity{PrivKey: privs[i]}
		unwrapped, err := ident.Unwrap([]RecipientStanza{stanzas[i]})
		if err != nil {
			t.Errorf("Unwrap %d: %v", i, err)
			continue
		}
		if !bytes.Equal(unwrapped, fileKey[:]) {
			t.Errorf("recipient %d: unwrapped key mismatch", i)
		}
	}
}
