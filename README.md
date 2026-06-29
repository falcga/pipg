# pipg

A lightweight tool for covert point-to-point data transfer utilizing raw ICMP Echo packets. Version 3.0 introduces end-to-end reliability, cryptographic security, RFC-compliant frame structures, and multi-session multiplexing.

## Features

- **ICMP tunneling** — transmit data over ICMP Echo Request/Reply (Type 8/0)
- **Encryption** — payload encryption via AES-256-GCM or ChaCha20-Poly1305 with a pre-shared key
- **Compression** — automatic zlib compression before encryption to minimize packet count
- **Reliability** — sliding-window retransmission with ACK-based acknowledgement
- **Multi-session** — concurrent streams identified by source IP + tunnel ID
- **Cross-platform** — zero-dependency builds for Linux and macOS (amd64 + arm64)

## Installation

Install the binary instantly for your system (Linux/macOS, amd64/arm64):

```bash
curl -sSL https://raw.githubusercontent.com/falcga/pipg/main/install.sh | bash
```

## Usage

### 1. Start Receiver

Run the listener first on the receiving machine:

```bash
# Unencrypted mode
sudo pipg receive <tunnel_id>

# Encrypted mode (AES-256-GCM)
sudo pipg receive -k "mysecretkey" <tunnel_id>

# Encrypted mode (ChaCha20-Poly1305)
sudo pipg receive -k "mysecretkey" --cipher chacha20 <tunnel_id>
```

### 2. Send Data

Transmit data from the sending host to the receiver:

```bash
# Unencrypted mode
sudo pipg send <receiver_ip> <tunnel_id> "your message here"

# Encrypted mode (AES-256-GCM)
sudo pipg send -k "mysecretkey" <receiver_ip> <tunnel_id> "your message here"

# Encrypted mode (ChaCha20-Poly1305)
sudo pipg send -k "mysecretkey" --cipher chacha20 <receiver_ip> <tunnel_id> "your message here"
```

> **Note:** `<tunnel_id>` must be a valid 16-bit integer (decimal or hex format like `0x1234`) and must match on both sides.

### CLI Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-k`, `--key` | string | (empty) | Pre-shared cryptographic key for encryption (omit for unencrypted mode) |
| `--cipher` | string | `aes-gcm` | Cipher algorithm: `aes-gcm` or `chacha20` |
| `-c`, `--chunk` | int | 56 | ICMP payload size limit per packet (bytes) |
| `-i`, `--interval` | duration | 1s | Delay between consecutive packet transmissions |
| `-t`, `--timeout` | duration | 5s | Session idle timeout / retransmission wait |

## Build from Source

```bash
# Linux amd64
GOOS=linux GOARCH=amd64 go build -o pipg-linux-amd64 .

# Linux arm64
GOOS=linux GOARCH=arm64 go build -o pipg-linux-arm64 .

# macOS amd64
GOOS=darwin GOARCH=amd64 go build -o pipg-darwin-amd64 .

# macOS arm64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o pipg-darwin-arm64 .
```

## Requirements

- **Root/administrator privileges** required for raw socket access (`SOCK_RAW`)
- **Linux** or **macOS** operating system
- **No external dependencies** — `CGO_ENABLED=0` compatible builds