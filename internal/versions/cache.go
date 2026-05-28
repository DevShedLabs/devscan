package versions

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const versionCacheTTL = 7 * 24 * time.Hour

type versionCacheEntry struct {
	CachedAt time.Time `json:"cached_at"`
	Version  string    `json:"version"`
}

func cacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "devscan", "versions")
	return dir, os.MkdirAll(dir, 0700)
}

func cacheKey(runtime string) string {
	h := sha256.New()
	fmt.Fprint(h, runtime)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func loadCached(runtime string) (string, bool) {
	dir, err := cacheDir()
	if err != nil {
		return "", false
	}

	data, err := os.ReadFile(filepath.Join(dir, cacheKey(runtime)+".json"))
	if err != nil {
		return "", false
	}

	var entry versionCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return "", false
	}

	if time.Since(entry.CachedAt) > versionCacheTTL {
		return "", false
	}

	return entry.Version, true
}

func saveCached(runtime, version string) {
	dir, err := cacheDir()
	if err != nil {
		return
	}

	entry := versionCacheEntry{
		CachedAt: time.Now(),
		Version:  version,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	tmp := filepath.Join(dir, cacheKey(runtime)+".tmp")
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	os.Rename(tmp, filepath.Join(dir, cacheKey(runtime)+".json"))
}
