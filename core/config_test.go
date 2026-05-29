package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigValidate(t *testing.T) {
	cf := &Conf{
		Version: ConfVersion,
		Argon2ID: Argon2Params{
			Time:    Argon2MinTime,
			Memory:  Argon2MinMemoryKB,
			Threads: Argon2MinThreads,
		},
	}
	if err := cf.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Time too low
	cf2 := &Conf{Argon2ID: Argon2Params{Time: 1, Memory: Argon2MinMemoryKB, Threads: Argon2MinThreads}}
	if err := cf2.Validate(); err == nil {
		t.Error("expected error for low time")
	}

	// Memory too low
	cf3 := &Conf{Argon2ID: Argon2Params{Time: Argon2MinTime, Memory: 1024, Threads: Argon2MinThreads}}
	if err := cf3.Validate(); err == nil {
		t.Error("expected error for low memory")
	}

	// Threads too low
	cf4 := &Conf{Argon2ID: Argon2Params{Time: Argon2MinTime, Memory: Argon2MinMemoryKB, Threads: 1}}
	if err := cf4.Validate(); err == nil {
		t.Error("expected error for low threads")
	}
}

func TestCreator(t *testing.T) {
	c := Creator()
	if c == "" {
		t.Error("Creator returned empty")
	}
}

func TestConfigSaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.conf")

	cf := &Conf{
		Version:   ConfVersion,
		Salt:      []byte("test-salt-1234567890"),
		CreatedBy: Creator(),
		Argon2ID: Argon2Params{
			Time:    Argon2MinTime,
			Memory:  Argon2MinMemoryKB,
			Threads: Argon2MinThreads,
		},
	}

	if err := Save(path, cf); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.Version != ConfVersion {
		t.Errorf("version = %d, want %d", loaded.Version, ConfVersion)
	}
	if loaded.Argon2ID.Time != Argon2MinTime {
		t.Errorf("time = %d, want %d", loaded.Argon2ID.Time, Argon2MinTime)
	}
	if loaded.Argon2ID.Memory != Argon2MinMemoryKB {
		t.Errorf("memory = %d, want %d", loaded.Argon2ID.Memory, Argon2MinMemoryKB)
	}
	if loaded.Argon2ID.Threads != Argon2MinThreads {
		t.Errorf("threads = %d, want %d", loaded.Argon2ID.Threads, Argon2MinThreads)
	}
}

func TestConfigLoadFileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/SealGo.conf")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestConfigLoadEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.conf")
	os.WriteFile(path, []byte{}, 0600)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestConfigLoadDirectory(t *testing.T) {
	_, err := Load(t.TempDir())
	if err == nil {
		t.Fatal("expected error when loading a directory")
	}
}

func TestConfigLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.conf")
	os.WriteFile(path, []byte("{invalid json"), 0600)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestConfigLoadInvalidVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "badver.conf")
	os.WriteFile(path, []byte(`{"Version":0}`), 0600)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for version 0")
	}
}

func TestConfigSaveEmptyPath(t *testing.T) {
	// Save with empty path should use default confPath
	// This might try to write to home dir, so we just test it doesn't panic
	cf := &Conf{
		Version: ConfVersion,
		Argon2ID: Argon2Params{
			Time:    Argon2MinTime,
			Memory:  Argon2MinMemoryKB,
			Threads: Argon2MinThreads,
		},
	}

	// Temporarily set env to a test path
	t.Setenv("SEALGO_CONF", filepath.Join(t.TempDir(), "SealGo.conf"))
	if err := Save("", cf); err != nil {
		t.Fatalf("Save with empty path: %v", err)
	}
}

func TestConfPath(t *testing.T) {
	// With env var
	t.Setenv("SEALGO_CONF", "/custom/path/SealGo.conf")
	got := confPath()
	if got != "/custom/path/SealGo.conf" {
		t.Errorf("confPath with env = %q", got)
	}
}

func TestConfigLoadWithEnvPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env.conf")
	t.Setenv("SEALGO_CONF", path)

	cf := &Conf{
		Version: ConfVersion,
		Argon2ID: Argon2Params{
			Time:    Argon2MinTime,
			Memory:  Argon2MinMemoryKB,
			Threads: Argon2MinThreads,
		},
	}
	Save(path, cf)

	loaded, err := Load("")
	if err != nil {
		t.Fatalf("Load with env path: %v", err)
	}
	if loaded.Version != ConfVersion {
		t.Errorf("version = %d", loaded.Version)
	}
}

func TestConfigValidateOK(t *testing.T) {
	cf := &Conf{
		Argon2ID: Argon2Params{
			Time:    Argon2MinTime,
			Memory:  Argon2MinMemoryKB + 1,
			Threads: Argon2MinThreads + 1,
		},
	}
	if err := cf.Validate(); err != nil {
		t.Errorf("expected valid: %v", err)
	}
}