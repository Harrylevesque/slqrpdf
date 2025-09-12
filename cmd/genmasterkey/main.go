package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// TODO(tool-genmasterkey-kms): Add option to fetch/generate key from external KMS instead of local file.
// TODO(tool-genmasterkey-backup): Provide encrypted backup output (e.g., print wrapped key with passphrase).
// TODO(tool-genmasterkey-rotate): Add --rotate flag to archive old key & create new with version tag.
// TODO(tool-genmasterkey-dryrun): Support --dry-run to show prospective key without writing.
// TODO(tool-genmasterkey-format): Allow output in base64 or raw binary (flags).
// TODO(tool-genmasterkey-perms): Verify file permissions after write (fail if too permissive).
// TODO(tool-genmasterkey-confirm): Add interactive confirmation when overwriting via --force.

func main() {
	const keyFile = "master.key"
	if _, err := os.Stat(keyFile); err == nil {
		fmt.Fprintf(os.Stderr, "Error: %s already exists. Refusing to overwrite.\n", keyFile)
		os.Exit(1)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating random key: %v\n", err)
		os.Exit(1)
	}
	hexKey := hex.EncodeToString(key)
	if err := os.WriteFile(keyFile, []byte(hexKey+"\n"), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", keyFile, err)
		os.Exit(1)
	}
	fmt.Printf("Master key written to %s\n", keyFile)
}
