package core

import (
	"testing"
)

func TestFeatureNameOf(t *testing.T) {
	tests := []struct {
		flag FeatureFlag
		name string
	}{
		{FlagXChaCha20Poly1305, "FlagXChaCha20Poly1305"},
		{FlagArgon2id, "FlagArgon2id"},
		{FlagHKDF, "FlagHKDF"},
		{FlagXAttrs, "FlagXAttrs"},
		{FlagNone, ""},
		{FeatureFlag(999), ""},
	}

	for _, tt := range tests {
		got := NameOf(tt.flag)
		if got != tt.name {
			t.Errorf("NameOf(%d) = %q, want %q", tt.flag, got, tt.name)
		}
	}
}

func TestFeatureIsKnown(t *testing.T) {
	if !IsKnown(FlagXChaCha20Poly1305) {
		t.Error("FlagXChaCha20Poly1305 should be known")
	}
	if IsKnown(FeatureFlag(999)) {
		t.Error("FeatureFlag(999) should not be known")
	}
}

func TestAllSupportedFlags(t *testing.T) {
	flags := AllSupportedFlags()
	if len(flags) == 0 {
		t.Fatal("AllSupportedFlags returned empty")
	}

	seen := make(map[FeatureFlag]bool)
	for _, f := range flags {
		if seen[f] {
			t.Errorf("duplicate flag %d", f)
		}
		seen[f] = true
		if !IsKnown(f) {
			t.Errorf("flag %d from AllSupportedFlags is not known", f)
		}
	}

	// Should include all known flags
	if !seen[FlagXChaCha20Poly1305] {
		t.Error("missing FlagXChaCha20Poly1305")
	}
	if !seen[FlagArgon2id] {
		t.Error("missing FlagArgon2id")
	}
	if !seen[FlagHKDF] {
		t.Error("missing FlagHKDF")
	}
}

func TestSupportedFeatures(t *testing.T) {
	features := SupportedFeatures()
	if len(features) == 0 {
		t.Fatal("SupportedFeatures returned empty")
	}
}

func TestNegotiate(t *testing.T) {
	// Known flags should pass
	if err := Negotiate([]FeatureFlag{FlagXChaCha20Poly1305, FlagArgon2id}); err != nil {
		t.Errorf("known flags should pass: %v", err)
	}

	// Empty should pass
	if err := Negotiate(nil); err != nil {
		t.Errorf("nil should pass: %v", err)
	}

	// Unknown flag should fail
	if err := Negotiate([]FeatureFlag{FeatureFlag(999)}); err == nil {
		t.Error("unknown flag should fail")
	}

	// FlagNone should pass
	if err := Negotiate([]FeatureFlag{FlagNone}); err != nil {
		t.Errorf("FlagNone should pass: %v", err)
	}
}

func TestReverseLookup(t *testing.T) {
	name, ok := reverseLookup(FlagXChaCha20Poly1305)
	if !ok {
		t.Error("reverseLookup should find known flag")
	}
	if name != "FlagXChaCha20Poly1305" {
		t.Errorf("got name %q", name)
	}

	_, ok = reverseLookup(FeatureFlag(999))
	if ok {
		t.Error("reverseLookup should not find unknown flag")
	}
}