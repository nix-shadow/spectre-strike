package cache

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

type Cache struct {
	store       map[string]*CacheEntry
	mu          sync.RWMutex
	ttl         time.Duration
	filePath    string
	db          *bolt.DB
	stopCleanup chan struct{}
	stopOnce    sync.Once
}

const cacheBucket = "cache_entries"

type CacheEntry struct {
	Key       string      `json:"key"`
	Value     interface{} `json:"value"`
	ExpiresAt time.Time   `json:"expires_at"`
	CreatedAt time.Time   `json:"created_at"`
}

func New(ttl time.Duration, filePath string) *Cache {
	c := &Cache{
		store:       make(map[string]*CacheEntry),
		ttl:         ttl,
		filePath:    filePath,
		stopCleanup: make(chan struct{}),
	}

	// Open bolt DB for persistence if a filePath is provided
	if filePath != "" {
		// DB file will be the provided path (allow .db extension)
		db, err := bolt.Open(filePath, 0600, &bolt.Options{Timeout: 1 * time.Second})
		if err != nil {
			log.Printf("cache: failed to open bolt DB %s: %v", filePath, err)
		} else {
			c.db = db
			// ensure bucket exists
			_ = db.Update(func(tx *bolt.Tx) error {
				_, err := tx.CreateBucketIfNotExists([]byte(cacheBucket))
				return err
			})
		}
	}

	// Load either from DB (if available) or fallback to JSON file
	c.load()
	return c
}

func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	c.store[key] = &CacheEntry{
		Key:       key,
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
		CreatedAt: time.Now(),
	}
	// Snapshot entries to persist outside lock
	entries := make([]*CacheEntry, 0, len(c.store))
	for _, entry := range c.store {
		entries = append(entries, entry)
	}
	c.mu.Unlock()

	if c.filePath != "" {
		if err := c.persistToFile(entries); err != nil {
			log.Printf("cache: persist failed on Set: %v", err)
		}
	}
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	entry, exists := c.store[key]
	if !exists {
		c.mu.RUnlock()
		return nil, false
	}

	// Check expiry
	if time.Now().After(entry.ExpiresAt) {
		c.mu.RUnlock()
		// Acquire write lock to delete expired entry
		c.mu.Lock()
		delete(c.store, key)
		// prepare entries for persistence outside the lock
		entries := make([]*CacheEntry, 0, len(c.store))
		for _, e := range c.store {
			entries = append(entries, e)
		}
		c.mu.Unlock()
		// Persist changes (best-effort)
		if c.filePath != "" {
			if err := c.persistToFile(entries); err != nil {
				log.Printf("cache: failed to persist after expiry deletion: %v", err)
			}
		}
		return nil, false
	}

	value := entry.Value
	c.mu.RUnlock()
	return value, true
}

func (c *Cache) Delete(key string) {
	c.mu.Lock()
	delete(c.store, key)
	entries := make([]*CacheEntry, 0, len(c.store))
	for _, entry := range c.store {
		entries = append(entries, entry)
	}
	c.mu.Unlock()

	if c.db != nil {
		if err := c.deleteFromDB(key); err != nil {
			log.Printf("cache: db delete failed: %v", err)
		}
	} else if c.filePath != "" {
		if err := c.persistToFile(entries); err != nil {
			log.Printf("cache: persist failed on Delete: %v", err)
		}
	}
}

func (c *Cache) Clear() {
	c.mu.Lock()
	c.store = make(map[string]*CacheEntry)
	c.mu.Unlock()

	if c.db != nil {
		if err := c.clearDB(); err != nil {
			log.Printf("cache: db clear failed: %v", err)
		}
	} else if c.filePath != "" {
		if err := c.persistToFile([]*CacheEntry{}); err != nil {
			log.Printf("cache: persist failed on Clear: %v", err)
		}
	}
}

func (c *Cache) Hash(data string) string {
	hash := md5.Sum([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (c *Cache) cleanup() {
	c.mu.Lock()
	now := time.Now()
	deletedKeys := make([]string, 0)
	for key, entry := range c.store {
		if now.After(entry.ExpiresAt) {
			delete(c.store, key)
			deletedKeys = append(deletedKeys, key)
		}
	}
	entries := make([]*CacheEntry, 0, len(c.store))
	for _, e := range c.store {
		entries = append(entries, e)
	}
	c.mu.Unlock()

	// Persist changes to DB if available
	if c.db != nil {
		_ = c.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(cacheBucket))
			for _, k := range deletedKeys {
				b.Delete([]byte(k))
			}
			// write remaining entries
			for _, e := range entries {
				data, _ := json.Marshal(e)
				b.Put([]byte(e.Key), data)
			}
			return nil
		})
	} else if c.filePath != "" {
		if err := c.persistToFile(entries); err != nil {
			log.Printf("cache: persist failed during cleanup: %v", err)
		}
	}
}

func (c *Cache) load() {
	// Prefer DB when available
	if c.db != nil {
		_ = c.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(cacheBucket))
			if b == nil {
				return nil
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			now := time.Now()
			b.ForEach(func(k, v []byte) error {
				var entry CacheEntry
				if err := json.Unmarshal(v, &entry); err != nil {
					return nil
				}
				if now.Before(entry.ExpiresAt) {
					c.store[string(k)] = &entry
				}
				return nil
			})
			return nil
		})
		return
	}

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

	// If we have a DB configured, migrate JSON entries into DB for future runs
	if c.db != nil {
		go func() {
			_ = c.db.Update(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(cacheBucket))
				if b == nil {
					return nil
				}
				for _, e := range entries {
					if time.Now().Before(e.ExpiresAt) {
						data, _ := json.Marshal(e)
						b.Put([]byte(e.Key), data)
					}
				}
				return nil
			})
		}()
	}
}

// persistToFile remains for backward compatibility (writes JSON) but DB is preferred.
func (c *Cache) persistToFile(entries []*CacheEntry) error {
	if c.filePath == "" {
		return nil
	}

	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(c.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmp := c.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	// Rename is atomic on most platforms
	if err := os.Rename(tmp, c.filePath); err != nil {
		return err
	}
	return nil
}

// persistToDB writes a single entry to the bolt DB
func (c *Cache) persistToDB(entry *CacheEntry) error {
	if c.db == nil {
		return nil
	}
	return c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(cacheBucket))
		if b == nil {
			return nil
		}
		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return b.Put([]byte(entry.Key), data)
	})
}

// deleteFromDB removes a key from the bolt DB
func (c *Cache) deleteFromDB(key string) error {
	if c.db == nil {
		return nil
	}
	return c.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(cacheBucket))
		if b == nil {
			return nil
		}
		return b.Delete([]byte(key))
	})
}

// clearDB removes all keys from the bucket
func (c *Cache) clearDB() error {
	if c.db == nil {
		return nil
	}
	return c.db.Update(func(tx *bolt.Tx) error {
		return tx.DeleteBucket([]byte(cacheBucket))
	})
}

func (c *Cache) StartCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				c.cleanup()
			case <-c.stopCleanup:
				ticker.Stop()
				return
			}
		}
	}()
}

// StopCleanup stops the background cleanup ticker. Safe to call multiple times.
func (c *Cache) StopCleanup() {
	c.stopOnce.Do(func() { close(c.stopCleanup) })
}

// Close closes the cache DB if open and stops cleanup.
func (c *Cache) Close() error {
	// Stop the cleanup goroutine first
	c.StopCleanup()
	if c.db != nil {
		if err := c.db.Close(); err != nil {
			return err
		}
		c.db = nil
	}
	return nil
}
