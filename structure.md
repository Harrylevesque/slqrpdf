slqrpdf/
├── cmd/
│   └── server/
│       └── main.go                # Entrypoint, loads encrypted config, starts server
│
├── internal/
│   ├── api/
│   │   ├── handlers.go            # Endpoint handlers
│   │   ├── middleware.go          # Logging, auth, recovery
│   │   └── router.go              # Route setup
│   │
│   ├── auth/
│   │   ├── login.go               # Passkey login logic
│   │   ├── register.go            # Registration flow
│   │   └── session.go             # Ephemeral session validation
│   │
│   ├── certs/
│   │   ├── cert_manager.go        # Manage encrypted certs on disk
│   │   └── cert_verify.go         # Verify decrypted certs
│   │
│   ├── crypto/
│   │   ├── keys.go                # Generate long/short/mash/TOTP seeds
│   │   ├── hash.go                # SHA256/SHA3/etc
│   │   ├── file_encrypt.go        # Encrypt/decrypt files (AES-GCM or XChaCha20)
│   │   └── signer.go              # Digital signatures
│   │
│   ├── files/
│   │   ├── user_store.go          # Handle encrypted user files
│   │   ├── key_store.go           # Encrypted key file management
│   │   └── qr_store.go            # Encrypted QR rotation files
│   │
│   ├── jobs/
│   │   └── rotator.go             # Regenerate encrypted QR/key files
│   │
│   ├── models/
│   │   └── user.go                # User + Session structs
│   │
│   ├── qr/
│   │   ├── generator.go           # Build QR + PDF417 + DataMatrix payloads
│   │   └── validator.go           # Validate decoded QR payloads
│   │
│   ├── storage/
│   │   ├── index.go               # Small index in MySQL (points to file paths)
│   │   └── fs.go                  # File system helpers
│   │
│   └── utils/
│       ├── config.go              # Loads encrypted config.json.enc
│       ├── logger.go              # Logging
│       └── errors.go              # Custom errors
│
├── encrypted_data/                # All encrypted blobs live here
│   ├── users/
│   │   ├── user_123.json.enc
│   │   └── user_456.json.enc
│   ├── keys/
│   │   ├── keyset_123.json.enc
│   │   └── keyset_456.json.enc
│   └── qr/
│       ├── qr_001.dat.enc
│       └── qr_002.dat.enc
│
├── test/
│   ├── api_test.go
│   ├── crypto_test.go
│   └── file_encrypt_test.go
│
├── configs/
│   └── config.json.enc            # Fully encrypted config
│
├── migrations/                    # Still needed for MySQL metadata
│   └── 001_init.sql
│
├── Dockerfile
├── docker-compose.yml
├── go.mod
├── go.sum
├── Makefile
└── README.md
