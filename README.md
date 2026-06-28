# pipg

A lightweight tool for covert data transfer utilizing raw ICMP Echo packets.

---

## Installation

Install the binary instantly for your system (Linux/macOS, amd64/arm64):

```bash
curl -sSL https://raw.githubusercontent.com/falcga/pipg/main/install.sh | bash

```

---

## Usage

### 1. Start Receiver

Run the listener first on the receiving machine to await incoming data payloads.

```bash
# Requires root privileges to open raw network sockets
sudo pipg receive <tunnel_id>

```

### 2. Send Data

Transmit data from the sending host to the receiver's destination IP address.

```bash
sudo pipg send <receiver_ip> <tunnel_id> "your message here"

```

> **Note:** `<tunnel_id>` must be a valid 16-bit integer (decimal or hex format like `0x1234`) and must match on both sides.
