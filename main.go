package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func parseID(s string) (uint16, error) {
	base := 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		base = 16
		s = s[2:]
	}
	val, err := strconv.ParseUint(s, base, 16)
	if err != nil {
		return 0, err
	}
	return uint16(val), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func runSendCmd(args []string) {
	sendCmd := flag.NewFlagSet("send", flag.ExitOnError)
	keyStr := sendCmd.String("k", "", "encryption key (optional; if omitted, data is sent in plaintext)")
	cipherName := sendCmd.String("cipher", CIPHER_AES_GCM, fmt.Sprintf("cipher for encryption: %q or %q", CIPHER_AES_GCM, CIPHER_CHACHA20))
	chunkSize := sendCmd.Int("c", DEF_CHUNK_SIZE, "max ICMP payload size (bytes)")
	interval := sendCmd.Duration("i", DEF_INTERVAL, "delay between packets")
	timeout := sendCmd.Duration("t", DEF_TIMEOUT, "session idle timeout")
	sendCmd.Parse(args)

	parsed := sendCmd.Args()
	if len(parsed) < 3 {
		fmt.Fprintf(os.Stderr, "send: need <dest_host> <id> <message>\n")
		sendCmd.Usage()
		os.Exit(1)
	}
	host := parsed[0]
	id, err := parseID(parsed[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid ID: %v\n", err)
		os.Exit(1)
	}
	message := strings.Join(parsed[2:], " ")

	if *cipherName != CIPHER_AES_GCM && *cipherName != CIPHER_CHACHA20 {
		fmt.Fprintf(os.Stderr, "invalid cipher %q (use %q or %q)\n", *cipherName, CIPHER_AES_GCM, CIPHER_CHACHA20)
		os.Exit(1)
	}

	var key []byte
	if *keyStr != "" {
		key = deriveKey(*keyStr)
	}

	cfg := sendConfig{
		destHost:  host,
		tunnelID:  id,
		key:       key,
		cipher:    *cipherName,
		msg:       message,
		chunkSize: *chunkSize,
		interval:  *interval,
		timeout:   *timeout,
	}
	if err := runSend(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "send error: %v\n", err)
		os.Exit(1)
	}
}

func runRecvCmd(args []string) {
	recvCmd := flag.NewFlagSet("receive", flag.ExitOnError)
	keyStr := recvCmd.String("k", "", "encryption key (optional; omit for unencrypted mode)")
	cipherName := recvCmd.String("cipher", CIPHER_AES_GCM, fmt.Sprintf("cipher for decryption: %q or %q", CIPHER_AES_GCM, CIPHER_CHACHA20))
	timeout := recvCmd.Duration("t", DEF_TIMEOUT, "session idle timeout")
	recvCmd.Parse(args)

	parsed := recvCmd.Args()
	if len(parsed) < 1 {
		fmt.Fprintf(os.Stderr, "receive: need <id>\n")
		recvCmd.Usage()
		os.Exit(1)
	}
	id, err := parseID(parsed[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid ID: %v\n", err)
		os.Exit(1)
	}

	if *cipherName != CIPHER_AES_GCM && *cipherName != CIPHER_CHACHA20 {
		fmt.Fprintf(os.Stderr, "invalid cipher %q (use %q or %q)\n", *cipherName, CIPHER_AES_GCM, CIPHER_CHACHA20)
		os.Exit(1)
	}

	var key []byte
	if *keyStr != "" {
		key = deriveKey(*keyStr)
	}

	cfg := receiveConfig{
		tunnelID: id,
		key:      key,
		cipher:   *cipherName,
		timeout:  *timeout,
	}
	if err := runReceive(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "receive error: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage:\n  pipg send [flags] <dest_host> <id> <message>\n  pipg receive [flags] <id>\n")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "send":
		runSendCmd(os.Args[2:])
	case "receive":
		runRecvCmd(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
