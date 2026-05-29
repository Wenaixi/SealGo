// Package core provides SealGo configuration file handling.
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Version 保存 SealGo 版本号，由构建时 -ldflags="-X core.Version=X" 注入
var Version string

func init() {
	// 提供运行时默认值，防止空版本输出
	if Version == "" {
		Version = "dev"
	}
}

const (
	// ConfDefaultName 是默认配置文件名称。
	ConfDefaultName = ".SealGo.conf"
	// ConfVersion 是当前配置文件格式版本号。
	ConfVersion = 1

	// Argon2ID 最低安全参数。
	Argon2MinMemoryKB = uint64(131072) // 128 MB
	Argon2MinTime     = uint32(3)      // 迭代次数
	Argon2MinThreads  = uint8(2)
)

// confPath 返回配置文件路径，优先使用环境变量 SEALGO_CONF。
func confPath() string {
	if envPath := os.Getenv("SEALGO_CONF"); envPath != "" {
		return envPath
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ConfDefaultName)
}

// Argon2Params 保存 Argon2 密钥派生参数。
type Argon2Params struct {
	Time    uint32 // 迭代次数
	Memory  uint64 // 内存大小（KB）
	Threads uint8  // 并行线程数
}

// Conf 是 SealGo 配置文件结构。
type Conf struct {
	Version   uint16       // 配置格式版本
	Salt      []byte       // Argon2 盐值
	Argon2ID  Argon2Params // Argon2 参数
	CreatedBy string       // 创建程序版本
	Features  []FeatureFlag // 启用的特性标志
}

// Load 从指定路径加载配置。
// 如果 path 为空，使用 SEALGO_CONF 环境变量或默认路径。
func Load(path string) (*Conf, error) {
	if path == "" {
		path = confPath()
	}

	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
		return nil, fmt.Errorf("config: stat file: %w", err)
	}
	if st.IsDir() {
		return nil, fmt.Errorf("config: path is a directory: %s", path)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read file: %w", err)
	}
	if len(data) == 0 {
		return nil, errors.New("config file is empty")
	}

	var cf Conf
	if err := json.Unmarshal(data, &cf); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	if cf.Version == 0 {
		return nil, errors.New("config: invalid version")
	}

	if err := cf.Validate(); err != nil {
		return nil, err
	}

	return &cf, nil
}

// Save 将配置保存到指定路径（原子写入：先写临时文件，再重命名）。
func Save(path string, cf *Conf) error {
	if path == "" {
		path = confPath()
	}

	if cf.Version == 0 {
		cf.Version = ConfVersion
	}

	data, err := json.MarshalIndent(cf, "", "\t")
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	data = append(data, '\n')

	// 原子写入：写临时文件 → 重命名
	tmp := path + ".tmp"
	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("config: create temp: %w", err)
	}
	if _, err := fd.Write(data); err != nil {
		fd.Close()
		os.Remove(tmp)
		return fmt.Errorf("config: write temp: %w", err)
	}
	if err := fd.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: close temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}

// Creator 返回标识本程序的创作者字符串。
func Creator() string {
	return "SealGo/" + Version
}

// Validate 校验配置参数是否满足最低安全阈值。
func (cf *Conf) Validate() error {
	if cf.Argon2ID.Memory < Argon2MinMemoryKB {
		return fmt.Errorf("Argon2id memory too low: %d KB (minimum: %d KB)", cf.Argon2ID.Memory, Argon2MinMemoryKB)
	}
	if cf.Argon2ID.Time < Argon2MinTime {
		return fmt.Errorf("Argon2id time too low: %d (minimum: %d)", cf.Argon2ID.Time, Argon2MinTime)
	}
	if cf.Argon2ID.Threads < Argon2MinThreads {
		return fmt.Errorf("Argon2id threads too low: %d (minimum: %d)", cf.Argon2ID.Threads, Argon2MinThreads)
	}
	return nil
}