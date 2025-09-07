package files

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	dbFileName = "qr_store.json"
)

// QRCode represents a QR code object
type QRCode struct {
	ID        string    `json:"id"`
	Data      string    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
}

// QRCodeStore manages the storage and retrieval of QR codes
type QRCodeStore struct {
	filePath string
	mu       sync.RWMutex
}

// NewQRCodeStore creates a new QRCodeStore
func NewQRCodeStore() *QRCodeStore {
	dir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	store := &QRCodeStore{
		filePath: filepath.Join(dir, dbFileName),
	}

	if err := store.load(); err != nil {
		fmt.Printf("Error loading QR code store: %v\n", err)
	}

	return store
}

// Save saves a QR code to the store
func (s *QRCodeStore) Save(qr *QRCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Load existing data
	var qrs []QRCode
	data, err := ioutil.ReadFile(s.filePath)
	if err == nil {
		json.Unmarshal(data, &qrs)
	}

	// Check if the QR code already exists
	for _, v := range qrs {
		if v.Data == qr.Data {
			return fmt.Errorf("QR code with the same data already exists")
		}
	}

	// Add the new QR code
	qr.ID = uuid.NewString()
	qr.CreatedAt = time.Now()
	qrs = append(qrs, *qr)

	// Save the data
	data, err = json.MarshalIndent(qrs, "", "  ")
	if err != nil {
		return err
	}

	return ioutil.WriteFile(s.filePath, data, 0644)
}

// GetAll retrieves all QR codes from the store
func (s *QRCodeStore) GetAll() ([]QRCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var qrs []QRCode
	data, err := ioutil.ReadFile(s.filePath)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(data, &qrs); err != nil {
		return nil, err
	}

	return qrs, nil
}

// Clear removes all QR codes from the store
func (s *QRCodeStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return os.Remove(s.filePath)
}

// load loads the QR codes from the file
func (s *QRCodeStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.Open(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, that's fine
		}
		return err
	}
	defer file.Close()

	var qrs []QRCode
	if err := json.NewDecoder(file).Decode(&qrs); err != nil {
		return err
	}

	return nil
}
