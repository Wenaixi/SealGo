package core

import (
	"crypto/hkdf"
	"crypto/sha256"
)

const (
	// HkdfInfoContent 是内容加密密钥派生的 info 数据。
	HkdfInfoContent = "XChaCha20-Poly1305 content encryption"
	// HkdfInfoFileName 是文件名加密密钥派生的 info 数据。
	HkdfInfoFileName = "file name encryption"
)

// HkdfDerive 使用 HKDF-SHA256（RFC 5869）从 masterkey 和 info 派生 outLen 字节。
// 返回派生密钥；出错时 panic（输入参数硬编码，不应出错）。
func HkdfDerive(masterkey []byte, info string, outLen int) []byte {
	key, err := hkdf.Key(sha256.New, masterkey, nil, info, outLen)
	if err != nil {
		panic("hkdfDerive: hkdf.Key failed: " + err.Error())
	}
	return key
}

// HkdfDeriveBytes 类似 HkdfDerive，但接受 []byte 类型的 info。
func HkdfDeriveBytes(masterkey []byte, info []byte, outLen int) []byte {
	key, err := hkdf.Key(sha256.New, masterkey, nil, string(info), outLen)
	if err != nil {
		panic("hkdfDeriveBytes: hkdf.Key failed: " + err.Error())
	}
	return key
}