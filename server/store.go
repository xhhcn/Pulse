package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"golang.org/x/crypto/bcrypt"
	bolt "go.etcd.io/bbolt"
)

const (
	defaultDBPath = "./data/metrics.db"
	bucketName    = "systems"
	tcpingBucket  = "tcping"
	configBucket  = "config"
	configKey     = "tcping"
	navbarConfigKey = "navbar"
	privacyConfigKey = "privacy"
	authBucket    = "auth"
	passwordKey   = "admin_password"
)

// Store represents the persistent storage
type Store struct {
	db *bolt.DB
}

// NewStore creates or opens the database
func NewStore(dbPath string) (*Store, error) {
	// Use default path if not specified
	if dbPath == "" {
		dbPath = defaultDBPath
	}

	// Create data directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Open database (creates if doesn't exist)
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{
		Timeout: 1 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Initialize buckets
	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return fmt.Errorf("failed to create bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(configBucket))
		if err != nil {
			return fmt.Errorf("failed to create config bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(tcpingBucket))
		if err != nil {
			return fmt.Errorf("failed to create tcping bucket: %w", err)
		}
		_, err = tx.CreateBucketIfNotExists([]byte(authBucket))
		if err != nil {
			return fmt.Errorf("failed to create auth bucket: %w", err)
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	log.Printf("✅ Database initialized: %s", dbPath)
	
	store := &Store{db: db}
	
	// Log current data count
	count := store.Count()
	if count == 0 {
		log.Printf("📦 Database is empty - waiting for first metrics")
	} else {
		log.Printf("📊 Loaded %d existing systems from database", count)
	}

	return store, nil
}

// Close closes the database
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Upsert inserts or updates a system metric
func (s *Store) Upsert(metric SystemMetric) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		// Serialize metric to JSON
		data, err := json.Marshal(metric)
		if err != nil {
			return fmt.Errorf("failed to marshal metric: %w", err)
		}

		// Store with ID as key
		if err := bucket.Put([]byte(metric.ID), data); err != nil {
			return fmt.Errorf("failed to put metric: %w", err)
		}

		return nil
	})
}

// List returns all system metrics sorted by order
func (s *Store) List() ([]SystemMetric, error) {
	var metrics []SystemMetric

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			var metric SystemMetric
			if err := json.Unmarshal(v, &metric); err != nil {
				log.Printf("⚠️ Failed to unmarshal metric %s: %v", string(k), err)
				return nil // Skip corrupted entry
			}
			metrics = append(metrics, metric)
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	// Sort by order field (ascending)
	sort.Slice(metrics, func(i, j int) bool {
		return metrics[i].Order < metrics[j].Order
	})

	return metrics, nil
}

// Get retrieves a specific system metric by ID
func (s *Store) Get(id string) (*SystemMetric, error) {
	var metric SystemMetric

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		data := bucket.Get([]byte(id))
		if data == nil {
			return fmt.Errorf("metric not found")
		}

		return json.Unmarshal(data, &metric)
	})

	if err != nil {
		return nil, err
	}

	return &metric, nil
}

// Delete removes a system metric by ID
func (s *Store) Delete(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket not found")
		}

		return bucket.Delete([]byte(id))
	})
}

// Count returns the number of systems in the database
func (s *Store) Count() int {
	count := 0
	s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketName))
		if bucket != nil {
			count = bucket.Stats().KeyN
		}
		return nil
	})
	return count
}

// DBPath returns the database file path from environment or default
func DBPath() string {
	if path := os.Getenv("DB_PATH"); path != "" {
		return path
	}
	return defaultDBPath
}

// TCPingResult represents a tcping result
type TCPingResult struct {
	ClientID  string     `json:"client_id"`
	Target    string     `json:"target"`    // Target address (e.g., "8.8.8.8:53")
	Latency   *float64   `json:"latency"`   // Latency in milliseconds (nil for timeout/failure)
	Timestamp time.Time  `json:"timestamp"`
}

// SaveTCPingResult saves a tcping result
func (s *Store) SaveTCPingResult(result TCPingResult) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		// Use timestamp + client_id + target as key for uniqueness
		key := fmt.Sprintf("%d_%s_%s", result.Timestamp.Unix(), result.ClientID, result.Target)
		data, err := json.Marshal(result)
		if err != nil {
			return fmt.Errorf("failed to marshal tcping result: %w", err)
		}

		return bucket.Put([]byte(key), data)
	})
}

// GetTCPingResults returns all tcping results for a client within 24 hours
// If target is provided, only returns results for that target
func (s *Store) GetTCPingResults(clientID string, target ...string) ([]TCPingResult, error) {
	var results []TCPingResult
	cutoffTime := time.Now().Add(-24 * time.Hour)
	filterTarget := ""
	if len(target) > 0 {
		filterTarget = target[0]
	}

	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				return nil // Skip corrupted entry
			}

			// Filter by client ID and time (within 24 hours)
			if result.ClientID == clientID && result.Timestamp.After(cutoffTime) {
				// If target filter is specified, only include matching results
				if filterTarget == "" || result.Target == filterTarget {
					results = append(results, result)
				}
			}
			return nil
		})
	})

	if err != nil {
		return nil, err
	}

	// Sort by timestamp (oldest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.Before(results[j].Timestamp)
	})

	return results, nil
}

// DeleteTCPingResultsByTarget deletes all tcping results for a specific target
func (s *Store) DeleteTCPingResultsByTarget(target string) error {
	var keysToDelete [][]byte

	// First pass: collect keys to delete
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				return nil // Skip corrupted entry
			}

			if result.Target == target {
				keysToDelete = append(keysToDelete, k)
			}
			return nil
		})
	})

	if err != nil {
		return err
	}

	// Second pass: delete entries
	if len(keysToDelete) > 0 {
		return s.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(tcpingBucket))
			if bucket == nil {
				return fmt.Errorf("tcping bucket not found")
			}

			for _, key := range keysToDelete {
				if err := bucket.Delete(key); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return nil
}

// DeleteTCPingResultsByClient deletes all tcping results for a specific client
func (s *Store) DeleteTCPingResultsByClient(clientID string) error {
	var keysToDelete [][]byte

	// First pass: collect keys to delete
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				return nil // Skip corrupted entry
			}

			if result.ClientID == clientID {
				keysToDelete = append(keysToDelete, k)
			}
			return nil
		})
	})

	if err != nil {
		return err
	}

	// Second pass: delete entries
	if len(keysToDelete) > 0 {
		return s.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(tcpingBucket))
			if bucket == nil {
				return fmt.Errorf("tcping bucket not found")
			}

			for _, key := range keysToDelete {
				if err := bucket.Delete(key); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return nil
}

// CleanupOldTCPingResults removes tcping results older than 24 hours
func (s *Store) CleanupOldTCPingResults() error {
	cutoffTime := time.Now().Add(-24 * time.Hour)
	var keysToDelete [][]byte

	// First pass: collect keys to delete
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(tcpingBucket))
		if bucket == nil {
			return fmt.Errorf("tcping bucket not found")
		}

		return bucket.ForEach(func(k, v []byte) error {
			var result TCPingResult
			if err := json.Unmarshal(v, &result); err != nil {
				// Corrupted entry, mark for deletion
				keysToDelete = append(keysToDelete, k)
				return nil
			}

			if result.Timestamp.Before(cutoffTime) {
				keysToDelete = append(keysToDelete, k)
			}
			return nil
		})
	})

	if err != nil {
		return err
	}

	// Second pass: delete old entries
	if len(keysToDelete) > 0 {
		return s.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket([]byte(tcpingBucket))
			if bucket == nil {
				return fmt.Errorf("tcping bucket not found")
			}

			for _, key := range keysToDelete {
				if err := bucket.Delete(key); err != nil {
					return err
				}
			}
			return nil
		})
	}

	return nil
}

// TCPingTargetEntry represents a single tcping target with name and address
type TCPingTargetEntry struct {
	Name    string `json:"name"`    // Display name for the target (e.g., "Google DNS")
	Address string `json:"address"` // Target address (e.g., "8.8.8.8:53")
}

// TCPingConfig represents the tcping configuration
type TCPingConfig struct {
	Targets      []TCPingTargetEntry `json:"targets"`      // List of target entries with name and address
	IntervalSecs int                 `json:"interval_secs"` // Polling interval in seconds
}

// GetTCPingConfig retrieves the tcping configuration
func (s *Store) GetTCPingConfig() (*TCPingConfig, error) {
	var config TCPingConfig
	
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}
		
		data := bucket.Get([]byte(configKey))
		if data == nil {
			// Return default config if not found: no targets, 60s interval
			config = TCPingConfig{
				Targets:      []TCPingTargetEntry{},
				IntervalSecs: 60,
			}
			return nil
		}
		
		// Try to unmarshal as new format first
		if err := json.Unmarshal(data, &config); err == nil {
			// Successfully unmarshaled as new format
			return nil
		}
		
		// Try to unmarshal as old format ([]string) for backward compatibility
		var oldTargets []string
		var oldConfig struct {
			Targets      []string `json:"targets"`
			IntervalSecs int      `json:"interval_secs"`
		}
		if err := json.Unmarshal(data, &oldConfig); err == nil {
			// Convert old format to new format
			config.IntervalSecs = oldConfig.IntervalSecs
			config.Targets = make([]TCPingTargetEntry, len(oldConfig.Targets))
			for i, addr := range oldConfig.Targets {
				config.Targets[i] = TCPingTargetEntry{
					Name:    addr, // Use address as default name
					Address: addr,
				}
			}
			return nil
		}
		
		// If both fail, try just the targets array
		if err := json.Unmarshal(data, &oldTargets); err == nil {
			// Convert old format to new format
			config.IntervalSecs = 60
			config.Targets = make([]TCPingTargetEntry, len(oldTargets))
			for i, addr := range oldTargets {
				config.Targets[i] = TCPingTargetEntry{
					Name:    addr, // Use address as default name
					Address: addr,
				}
			}
			return nil
		}
		
		// If all fail, return the original error
		return json.Unmarshal(data, &config)
	})
	
	if err != nil {
		return nil, err
	}
	
	return &config, nil
}

// SaveTCPingConfig saves the tcping configuration
func (s *Store) SaveTCPingConfig(config *TCPingConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}
		
		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		
		return bucket.Put([]byte(configKey), data)
	})
}

// CheckPasswordSet checks if a password has been set
func (s *Store) CheckPasswordSet() (bool, error) {
	var exists bool
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
		if bucket == nil {
			return nil
		}
		exists = bucket.Get([]byte(passwordKey)) != nil
		return nil
	})
	return exists, err
}

// SetPassword sets the admin password (hashed)
func (s *Store) SetPassword(password string) error {
	// Hash password with bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}
		return bucket.Put([]byte(passwordKey), hashedPassword)
	})
}

// VerifyPassword verifies the admin password
func (s *Store) VerifyPassword(password string) (bool, error) {
	var hashedPassword []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(authBucket))
		if bucket == nil {
			return fmt.Errorf("auth bucket not found")
		}
		hashedPassword = bucket.Get([]byte(passwordKey))
		if hashedPassword == nil {
			return fmt.Errorf("password not set")
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	return err == nil, nil
}

// GenerateAuthToken generates a random auth token
func GenerateAuthToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// NavbarConfig represents the navbar configuration
type NavbarConfig struct {
	Text string `json:"text"` // Custom text for navbar (default: "Pulse")
	Logo string `json:"logo"` // Custom logo URL or SVG (default: built-in SVG)
}

// GetNavbarConfig retrieves the navbar configuration
func (s *Store) GetNavbarConfig() (*NavbarConfig, error) {
	var config NavbarConfig
	
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}
		
		data := bucket.Get([]byte(navbarConfigKey))
		if data == nil {
			// Return default config if not found
			config = NavbarConfig{
				Text: "Pulse",
				Logo: "", // Empty means use default SVG
			}
			return nil
		}
		
		return json.Unmarshal(data, &config)
	})
	
	if err != nil {
		return nil, err
	}
	
	return &config, nil
}

// SaveNavbarConfig saves the navbar configuration
func (s *Store) SaveNavbarConfig(config *NavbarConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}
		
		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		
		return bucket.Put([]byte(navbarConfigKey), data)
	})
}

// PrivacyConfig represents the privacy configuration
type PrivacyConfig struct {
	Enabled          bool      `json:"enabled"`           // Whether privacy mode is enabled
	ShareToken       string    `json:"share_token"`       // Temporary share token
	TokenExpires     time.Time `json:"token_expires"`     // Token expiration time
	ExpiresInSeconds int       `json:"expires_in_seconds"` // Saved expiration seconds value for UI
}

// GetPrivacyConfig retrieves the privacy configuration
func (s *Store) GetPrivacyConfig() (*PrivacyConfig, error) {
	var config PrivacyConfig
	
	err := s.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}
		
		data := bucket.Get([]byte(privacyConfigKey))
		if data == nil {
			// Return default config if not found
			config = PrivacyConfig{
				Enabled:          false,
				ShareToken:       "",
				TokenExpires:     time.Time{},
				ExpiresInSeconds: 3600, // Default to 1 hour (3600 seconds)
			}
			return nil
		}
		
		return json.Unmarshal(data, &config)
	})
	
	if err != nil {
		return nil, err
	}
	
	return &config, nil
}

// SavePrivacyConfig saves the privacy configuration
func (s *Store) SavePrivacyConfig(config *PrivacyConfig) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(configBucket))
		if bucket == nil {
			return fmt.Errorf("config bucket not found")
		}
		
		data, err := json.Marshal(config)
		if err != nil {
			return fmt.Errorf("failed to marshal config: %w", err)
		}
		
		return bucket.Put([]byte(privacyConfigKey), data)
	})
}
