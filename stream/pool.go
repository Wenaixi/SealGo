package stream

import "sync"

// BufPool 管理加解密操作的可复用缓冲区，减少内存分配。
// 缓冲区归还前必须由调用方擦除敏感数据。
var BufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024) // 默认 64KB chunk
		return &buf
	},
}