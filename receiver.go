package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type receiveConfig struct {
	tunnelID uint16
	key      []byte
	cipher   string
	timeout  time.Duration
}

func openReceiveSocket() (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return 0, err
	}
	tv := unix.Timeval{Sec: 1, Usec: 0}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return 0, err
	}
	return fd, nil
}

func processPacket(buf []byte, n int, cfg receiveConfig) (string, uint16, []byte, error) {
	if n < 20 {
		return "", 0, nil, nil
	}
	ihl := int(buf[0]&0x0F) * 4
	if n < ihl+8 {
		return "", 0, nil, nil
	}
	srcIP := net.IP(buf[12:16]).String()
	icmpData := buf[ihl:n]
	if len(icmpData) < 8 || icmpData[0] != 8 {
		return "", 0, nil, nil
	}
	id := binary.BigEndian.Uint16(icmpData[4:6])
	if id != cfg.tunnelID {
		return "", 0, nil, nil
	}
	seq := binary.BigEndian.Uint16(icmpData[6:8])
	payload := icmpData[8:]

	var plain []byte
	if len(cfg.key) > 0 {
		if len(payload) < OVERHEAD {
			return "", 0, nil, nil
		}
		nonce := payload[:NONCE_SIZE]
		ciphertext := payload[NONCE_SIZE:]
		var err error
		plain, err = decryptChunk(cfg.key, nonce, ciphertext, cfg.cipher)
		if err != nil {
			return "", 0, nil, nil
		}
	} else {
		plain = make([]byte, len(payload))
		copy(plain, payload)
	}
	return srcIP, seq, plain, nil
}

func sendAck(fd int, buf []byte, n int, tunnelID uint16, seq uint16) {
	reply := icmpEchoReply(tunnelID, seq, nil)
	destAddr := &unix.SockaddrInet4{Port: 0}
	copy(destAddr.Addr[:], buf[12:16])
	if err := unix.Sendto(fd, reply, 0, destAddr); err != nil {
		fmt.Printf("failed to send ACK for seq %d: %v\n", seq, err)
	}
}

func expireSessions(sessions map[string]*reassembly, timeout time.Duration) {
	now := time.Now()
	for key, rb := range sessions {
		if now.Sub(rb.lastSeen) > timeout {
			if data, err := rb.assemble(); err != nil {
				fmt.Printf("error assembling from %s: %v\n", key, err)
			} else if len(data) > 0 {
				printMessage(key, data)
			}
			delete(sessions, key)
		}
	}
}

func printMessage(key string, data []byte) {
	if strings.Contains(string(data), "\x00") {
		fmt.Printf("binary from %s: %x...\n", key, data[:min(100, len(data))])
	} else {
		fmt.Printf("\nmessage from %s:\n%s\n\n", key, string(data))
	}
}

func runReceive(cfg receiveConfig) error {
	fd, err := openReceiveSocket()
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	sessions := make(map[string]*reassembly)
	var mu sync.Mutex

	if len(cfg.key) > 0 {
		fmt.Printf("Listening for tunnel ID %#x (encrypted, cipher: %s)...\n", cfg.tunnelID, cfg.cipher)
	} else {
		fmt.Printf("Listening for tunnel ID %#x (unencrypted)...\n", cfg.tunnelID)
	}

	buf := make([]byte, 65535)
	for {
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				mu.Lock()
				expireSessions(sessions, cfg.timeout)
				mu.Unlock()
				continue
			}
			return err
		}

		srcIP, seq, plain, err := processPacket(buf, n, cfg)
		if err != nil || plain == nil {
			continue
		}
		compositeKey := srcIP + "|" + strconv.Itoa(int(cfg.tunnelID))

		mu.Lock()
		rb, ok := sessions[compositeKey]
		if !ok {
			rb = newReassembly()
			sessions[compositeKey] = rb
		}
		rb.add(seq, plain)
		mu.Unlock()

		sendAck(fd, buf, n, cfg.tunnelID, seq)
	}
}
