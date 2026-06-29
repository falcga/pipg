package main

import "time"

const (
	DEF_CHUNK_SIZE = 56
	DEF_INTERVAL   = 1 * time.Second
	DEF_TIMEOUT    = 5 * time.Second
	WINDOW_SIZE    = 4
	MAX_RETRIES    = 3
	NONCE_SIZE     = 12
	TAG_SIZE       = 16
	OVERHEAD       = NONCE_SIZE + TAG_SIZE
)

const (
	CIPHER_AES_GCM  = "aes-gcm"
	CIPHER_CHACHA20 = "chacha20"
)
