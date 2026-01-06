package cache

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Cache struct {
	store    map[string]*CacheEntry
	mu       sync.RWMutex
	ttl      time.Duration
	filePath string
}

type CacheEntry struct {
	Key       string      `json:"key"`
	Value     interface{} `json:"value"`
	ExpiresAt time.Time   `json:"expires_at"`
	CreatedAt time.Time   `json:"created_at"`
}

func New(ttl time.Duration, filePath string) *Cache {
	c := &Cache{
		store:    make(map[string]*CacheEntry),
		ttl:      ttl,
		filePath: filePath,
	}
	c.load()
	return c
}

func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.store[key] = &CacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
		CreatedAt: time.Now(),
	}
	c.persist()
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.store[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		delete(c.store, key)
		return nil, false
	}

	return entry.Value, true
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, key)
	c.persist()
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store = make(map[string]*CacheEntry)
	c.persist()
}

func (c *Cache) Hash(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (c *Cache) cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for key, entry := range c.store {
		if now.After(entry.ExpiresAt) {
			delete(c.store, key)
		}
	}
}

func (c *Cache) load() {
	if c.filePath == "" {
		return
	}

	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return
	}

	var entries []*CacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for _, entry := range entries {
		if now.Before(entry.ExpiresAt) {
			c.store[entry.Key] = entry
		}
	}
}

func (c *Cache) persist() {
	if c.filePath == "" {
		return
	}

	entries := make([]*CacheEntry, 0, len(c.store))
	for _, entry := range c.store {
		entries = append(entries, entry)
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return
	}

	dir := filepath.Dir(c.filePath)
	os.MkdirAll(dir, 0755)
	os.WriteFile(c.filePath, data, 0644)
}

func (c *Cache) StartCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			c.cleanup()
		}
	}()
}
