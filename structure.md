slqrpdf/
├── cmd/                                # Entrypoints of the project (executable applications)
│   └── server/                         # Main server app
│       └── main.go                     # - Loads encrypted config (config.json.enc)
│                                         - Initializes logging, DB, storage, QR rotator jobs
│                                         - Starts HTTP server and routes
│                                         - Graceful shutdown handling
│                                         - Can be extended to support CLI flags (port, env)
│
├── internal/                            # Core application logic (private, not exposed)
│   ├── api/                             # HTTP API layer (REST/JSON endpoints)
│   │   ├── handlers.go                  # - Functions per endpoint (GetUser, CreateQR, etc.)
│   │   ├── middleware.go                # - Auth middleware (passkeys, sessions)
│   │                                      - Logging middleware (request/response timing)
│   │                                      - Recovery middleware (panic handling)
│   │   └── router.go                    # - Links routes to handlers
│   │                                      - Can handle versioning (v1, v2 API)
│   │
│   ├── auth/                            # Authentication & authorization
│   │   ├── login.go                     # - Passkey login flow
│   │                                      - Optional TOTP or session OTP
│   │   ├── register.go                  # - User registration (create encrypted user file)
│   │   └── session.go                   # - Ephemeral session management
│   │                                      - Session creation, expiration, validation
│   │                                      - Can support JWT or internal tokens
│   │
│   ├── certs/                           # Certificate management
│   │   ├── cert_manager.go              # - Create, rotate, store encrypted certificates
│   │   └── cert_verify.go               # - Verify authenticity and integrity of certs
│   │
│   ├── crypto/                           # Cryptography & security primitives
│   │   ├── keys.go                      # - Generate long/short/mash/TOTP seeds
│   │                                      - Secure key generation and storage helpers
│   │   ├── hash.go                      # - Hashing: SHA256, SHA3, or custom algorithms
│   │   ├── file_encrypt.go              # - Encrypt/decrypt files (AES-GCM, XChaCha20)
│   │                                      - Handles file padding, nonce generation
│   │   └── signer.go                    # - Digital signatures (sign/verify blobs)
│   │
│   ├── files/                            # File storage & management
│   │   ├── user_store.go                # - Create, read, update, delete encrypted user files
│   │   ├── key_store.go                 # - Manage encrypted keysets per user/device
│   │   └── qr_store.go                  # - Manage encrypted QR rotation files
│   │                                      - Handle rotation schedule & versioning
│   │
│   ├── jobs/                             # Background & periodic jobs
│   │   └── rotator.go                   # - Periodically regenerates encrypted QR/key files
│   │                                      - Ensures no QR is stale and rotation is synchronized
│   │
│   ├── models/                           # Data models / structs
│   │   └── user.go                       # - User struct (ID, name, roles)
│   │                                      - Session struct (token, expiry)
│   │                                      - Optional QR/device metadata structs
│   │
│   ├── qr/                               # QR code generation & validation
│   │   ├── generator.go                 # - Outer QR creation
│   │                                      - Embedded PDF417 with rotating DataMatrix payloads
│   │                                      - Configurable rotation timing
│   │   └── validator.go                 # - Decode QR, PDF417, DataMatrix
│   │                                      - Validate payload against encrypted storage
│   │
│   ├── storage/                          # Storage abstraction layer
│   │   ├── index.go                      # - MySQL index (maps encrypted files to users/QRs)
│   │   └── fs.go                         # - File system helpers (path, existence, cleanup)
│   │
│   └── utils/                            # Miscellaneous helpers
│       ├── config.go                     # - Load & decrypt config.json.enc
│       │                                      - Validate required fields (DB, server port, secrets)
│       ├── logger.go                     # - Centralized logging (levels, file/stdout)
│       └── errors.go                     # - Structured custom errors (NotFound, AuthFailed, QRExpired)
│
├── encrypted_data/                        # All encrypted blobs are stored here
│   ├── users/                             # Encrypted user JSON files
│   │   ├── user_123.json.enc
│   │   └── user_456.json.enc
│   ├── keys/                              # Encrypted key sets (per user/device)
│   │   ├── keyset_123.json.enc
│   │   └── keyset_456.json.enc
│   └── qr/                                # Rotating QR payloads
│       ├── qr_001.dat.enc
│       └── qr_002.dat.enc
│
├── test/                                  # Unit & integration tests
│   ├── api_test.go                        # - Test endpoints, middleware, responses
│   ├── crypto_test.go                     # - Test keygen, hashing, file encryption
│   └── file_encrypt_test.go               # - Test encryption/decryption correctness
│
├── configs/                               # Encrypted configuration files
│   └── config.json.enc                     # - JSON config encrypted for security
│                                             - Contains server, DB, and cryptography settings
│
├── migrations/                             # Database migrations for MySQL
│   └── 001_init.sql                        # - Initial schema setup (users, QR index, sessions)
│
├── Dockerfile                              # Instructions to build the container
├── docker-compose.yml                      # Orchestration (server + MySQL + optional redis/jobs)
├── go.mod                                  # Go module dependencies
├── go.sum                                  # Module checksums
├── Makefile                                # Common tasks: build, test, run, docker
└── README.md                               # Project overview, setup instructions, architecture notes
