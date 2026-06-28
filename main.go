package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const TUNNEL_ID = 0x1234
const TIMEOUT = 5 * time.Second      // if not set to 1 second the thing is WAY MORE SUSPICIOUS
const CHUNK_SIZE = 56                // more than 56 and sussy
const INTERVAL = 1 * time.Second     // more interval and sussy

func icmpEchoRequest(id uint16, seq uint16, payload []byte) []byte {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[4:6], id)
	binary.BigEndian.PutUint16(hdr[6:8], seq)
	packet := append(hdr, payload...)
	binary.BigEndian.PutUint16(packet[2:4], 0)
	checksum := icmpChecksum(packet)
	binary.BigEndian.PutUint16(packet[2:4], checksum)
	return packet
}

func icmpChecksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func runSend(destHost string, tunnelID uint16, message string) error {
	compressed := &bytes.Buffer{}
	w := zlib.NewWriter(compressed)
	if _, err := w.Write([]byte(message)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	data := compressed.Bytes()
	total := len(data)
	chunks := (total + CHUNK_SIZE - 1) / CHUNK_SIZE
	fmt.Printf("%d bytes, chunks: %d\n", total, chunks)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// REQ-1 & REQ-2: Resolve FQDN or literal IP address to IPv4
	ips, err := net.LookupIP(destHost)
	if err != nil {
		return fmt.Errorf("failed to resolve host %s: %v", destHost, err)
	}
	var dest net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			dest = v4
			break
		}
	}
	if dest == nil {
		return fmt.Errorf("no valid IPv4 address found for host %s", destHost)
	}

	addr := &unix.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dest)

	seq := uint16(1)
	for offset := 0; offset < total; offset += CHUNK_SIZE {
		end := offset + CHUNK_SIZE
		if end > total {
			end = total
		}
		chunk := data[offset:end]
		packet := icmpEchoRequest(tunnelID, seq, chunk)
		if err := unix.Sendto(fd, packet, 0, addr); err != nil {
			return err
		}
		fmt.Printf("%d: %d bytes\n", seq, len(chunk))
		seq++
		time.Sleep(INTERVAL)
	}
	fmt.Println("all sent")
	return nil
}

type fragment struct {
	seq   uint16
	parts [][]byte
}

type reassembly struct {
	fragments []fragment
	lastSeen  time.Time
}

func (r *reassembly) add(seq uint16, payload []byte) {
	r.fragments = append(r.fragments, fragment{seq: seq, parts: [][]byte{payload}})
	r.lastSeen = time.Now()
}

func (r *reassembly) assemble() ([]byte, error) {
	if len(r.fragments) == 0 {
		return nil, nil
	}
	for i := 0; i < len(r.fragments)-1; i++ {
		for j := i + 1; j < len(r.fragments); j++ {
			if r.fragments[i].seq > r.fragments[j].seq {
				r.fragments[i], r.fragments[j] = r.fragments[j], r.fragments[i]
			}
		}
	}
	var full []byte
	for _, f := range r.fragments {
		for _, part := range f.parts {
			full = append(full, part...)
		}
	}
	zr, err := zlib.NewReader(bytes.NewReader(full))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	decompressed, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	return decompressed, nil
}

func runReceive(tunnelID uint16) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	tv := unix.Timeval{Sec: 1, Usec: 0}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}

	buffers := make(map[string]*reassembly)
	var mu sync.Mutex

	fmt.Printf("id %#x...\n", tunnelID)

	for {
		buf := make([]byte, 65535)
		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				mu.Lock()
				now := time.Now()
				for srcIP, rb := range buffers {
					if now.Sub(rb.lastSeen) > TIMEOUT {
						if data, err := rb.assemble(); err != nil {
							fmt.Printf("error %s. raw: %x...\n", srcIP, data[:min(100, len(data))])
						} else if len(data) > 0 {
							if strings.Contains(string(data), "\x00") {
								fmt.Printf("binary %s: %x...\n", srcIP, data[:min(100, len(data))])
							} else {
								fmt.Printf("\nmessage from %s\n%s\n\n", srcIP, string(data))
							}
						}
						delete(buffers, srcIP)
					}
				}
				mu.Unlock()
				continue
			}
			return err
		}
		if n < 20 {
			continue
		}
		ihl := int(buf[0]&0x0F) * 4
		if len(buf) < ihl {
			continue
		}
		srcIP := net.IP(buf[12:16]).String()
		icmpData := buf[ihl:n]
		if len(icmpData) < 8 {
			continue
		}
		icmp_type := icmpData[0]
		if icmp_type != 8 && icmp_type != 0 {
			continue
		}
		icmp_id := binary.BigEndian.Uint16(icmpData[4:6])
		if icmp_id != tunnelID {
			continue
		}
		icmp_seq := binary.BigEndian.Uint16(icmpData[6:8])
		payload := icmpData[8:]
		if len(payload) == 0 {
			continue
		}
		mu.Lock()
		rb, ok := buffers[srcIP]
		if !ok {
			rb = &reassembly{lastSeen: time.Now()}
			buffers[srcIP] = rb
		}
		rb.add(icmp_seq, payload)
		mu.Unlock()
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "pipg send <dest_host> <id> <message>  or  pipg receive <id>\n")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "send":
		if len(os.Args) < 5 {
			fmt.Fprintf(os.Stderr, "pipg send <dest_host> <id> <message>\n")
			os.Exit(1)
		}
		host := os.Args[2]
		id, err := parseID(os.Args[3])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid ID: %v\n", err)
			os.Exit(1)
		}
		message := strings.Join(os.Args[4:], " ")
		if err := runSend(host, id, message); err != nil {
			fmt.Fprintf(os.Stderr, "send error: %v\n", err)
			os.Exit(1)
		}

	case "receive":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "pipg receive <id>\n")
			os.Exit(1)
		}
		id, err := parseID(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid ID: %v\n", err)
			os.Exit(1)
		}
		if err := runReceive(id); err != nil {
			fmt.Fprintf(os.Stderr, "receive error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(1)
	}
}

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
