// Package core provides SealGo configuration and feature flags.
package core

import (
	"errors"
	"slices"
)

// FeatureFlag 表示一个特性标志。
type FeatureFlag int

const (
	FlagNone               FeatureFlag = iota
	FlagXChaCha20Poly1305              // XChaCha20-Poly1305 加密（已有）
	FlagArgon2id                       // Argon2id 密钥派生（已有）
	FlagHKDF                           // HKDF 子密钥派生（已有）
	FlagXAttrs                         // 扩展属性（预留）
)

// KnownFlags 将特性标志名称映射到 FeatureFlag 值。
var KnownFlags = map[string]FeatureFlag{
	"FlagXChaCha20Poly1305": FlagXChaCha20Poly1305,
	"FlagArgon2id":          FlagArgon2id,
	"FlagHKDF":              FlagHKDF,
	"FlagXAttrs":            FlagXAttrs,
}

// NameOf 返回特性标志的名称。
func NameOf(f FeatureFlag) string {
	for name, v := range KnownFlags {
		if v == f {
			return name
		}
	}
	return ""
}

// IsKnown 返回 f 是否为已知的特性标志。
func IsKnown(f FeatureFlag) bool {
	_, ok := reverseLookup(f)
	return ok
}

// reverseLookup 返回标志对应的名称和是否存在。
func reverseLookup(f FeatureFlag) (string, bool) {
	for name, v := range KnownFlags {
		if v == f {
			return name, true
		}
	}
	return "", false
}

// AllSupportedFlags 返回当前支持的所有特性标志。
func AllSupportedFlags() []FeatureFlag {
	flags := make([]FeatureFlag, 0, len(KnownFlags))
	for _, f := range KnownFlags {
		flags = append(flags, f)
	}
	slices.Sort(flags)
	return flags
}

// SupportedFeatures 返回支持的特性标志列表，保留以保持向前兼容。
func SupportedFeatures() []FeatureFlag {
	return AllSupportedFlags()
}

// Negotiate 校验保存的特性标志，遇到未知标志时返回错误。
func Negotiate(savedFlags []FeatureFlag) error {
	for _, f := range savedFlags {
		if f != FlagNone && !IsKnown(f) {
			name := NameOf(f)
			if name == "" {
				return errors.New("unknown feature flag")
			}
			return errors.New("unknown feature flag: " + name)
		}
	}
	return nil
}