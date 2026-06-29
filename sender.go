package main

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type pendingPacket struct {
	seq     uint16
	data    []byte
	timer   *time.Timer
	retries int
}

type senderState struct {
	mu         sync.Mutex
	pending    map[uint16]*pendingPacket
	nextSeq    uint16
	windowBase uint16
	allSent    bool
	done       chan struct{}
	timeout    time.Duration
}

func (s *senderState) addPending(seq uint16, data []byte, retransmitFn func(uint16)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := &pendingPacket{
		seq:  seq,
		data: data,
	}
	p.timer = time.AfterFunc(s.timeout, func() {
		retransmitFn(seq)
	})
	s.pending[seq] = p
}

func (s *senderState) ackReceived(seq uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[seq]
	if !ok {
		return
	}
	p.timer.Stop()
	delete(s.pending, seq)
	if seq == s.windowBase {
		for {
			if _, ok := s.pending[s.windowBase]; ok {
				break
			}
			s.windowBase++
		}
	}
}

func (s *senderState) retransmit(seq uint16, sendFn func(uint16, []byte)) {
	s.mu.Lock()
	p, ok := s.pending[seq]
	if !ok {
		s.mu.Unlock()
		return
	}
	if p.retries >= MAX_RETRIES {
		delete(s.pending, seq)
		s.mu.Unlock()
		return
	}
	p.retries++
	p.timer.Stop()
	p.timer = time.AfterFunc(s.timeout, func() {
		s.retransmit(seq, sendFn)
	})
	s.mu.Unlock()
	sendFn(seq, p.data)
}

type sendConfig struct {
	destHost  string
	tunnelID  uint16
	key       []byte
	cipher    string
	msg       string
	chunkSize int
	interval  time.Duration
	timeout   time.Duration
}

func prepareSendData(cfg sendConfig) ([]byte, int, int, error) {
	if len(cfg.key) > 0 {
		compressed := &bytes.Buffer{}
		w := zlib.NewWriter(compressed)
		if _, err := w.Write([]byte(cfg.msg)); err != nil {
			return nil, 0, 0, err
		}
		if err := w.Close(); err != nil {
			return nil, 0, 0, err
		}
		plainData := compressed.Bytes()
		total := len(plainData)
		maxPlain := cfg.chunkSize - OVERHEAD
		if maxPlain <= 0 {
			return nil, 0, 0, fmt.Errorf("chunk size too small (need at least %d bytes)", OVERHEAD+1)
		}
		fmt.Printf("%d bytes, chunks: %d (max plaintext per chunk: %d)\n", total, (total+maxPlain-1)/maxPlain, maxPlain)
		return plainData, total, maxPlain, nil
	}
	plainData := []byte(cfg.msg)
	total := len(plainData)
	if total == 0 {
		return nil, 0, 0, fmt.Errorf("message is empty")
	}
	if cfg.chunkSize <= 0 {
		return nil, 0, 0, fmt.Errorf("chunk size must be positive")
	}
	fmt.Printf("%d bytes, chunks: %d (max per chunk: %d, unencrypted)\n", total, (total+cfg.chunkSize-1)/cfg.chunkSize, cfg.chunkSize)
	return plainData, total, cfg.chunkSize, nil
}

func resolveDest(host string) (net.IP, *unix.SockaddrInet4, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve host: %v", err)
	}
	var dest net.IP
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			dest = v4
			break
		}
	}
	if dest == nil {
		return nil, nil, fmt.Errorf("no IPv4 address for %s", host)
	}
	addr := &unix.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dest)
	return dest, addr, nil
}

func openRawSocket(timeout time.Duration) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		return 0, err
	}
	tv := unix.NsecToTimeval(int64(timeout))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return 0, err
	}
	return fd, nil
}

func startAckListener(fd int, state *senderState, dest net.IP, tunnelID uint16) chan uint16 {
	ackCh := make(chan uint16, 10)
	go func() {
		defer close(ackCh)
		buf := make([]byte, 65535)
		for {
			select {
			case <-state.done:
				return
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					continue
				}
				fmt.Printf("recv error: %v\n", err)
				return
			}
			if n < 20 {
				continue
			}
			ihl := int(buf[0]&0x0F) * 4
			if n < ihl+8 {
				continue
			}
			srcIP := net.IP(buf[12:16])
			if !srcIP.Equal(dest) {
				continue
			}
			icmpData := buf[ihl:n]
			if len(icmpData) < 8 || icmpData[0] != 0 {
				continue
			}
			id := binary.BigEndian.Uint16(icmpData[4:6])
			if id != tunnelID {
				continue
			}
			seq := binary.BigEndian.Uint16(icmpData[6:8])
			select {
			case ackCh <- seq:
			default:
			}
		}
	}()
	return ackCh
}

func sendChunk(fd int, addr *unix.SockaddrInet4, tunnelID uint16, seq uint16, payload []byte) {
	packet := icmpEchoRequest(tunnelID, seq, payload)
	if err := unix.Sendto(fd, packet, 0, addr); err != nil {
		fmt.Printf("send error for seq %d: %v\n", seq, err)
	}
}

type sendLoopState struct {
	state      *senderState
	ackCh      chan uint16
	plainData  []byte
	total      int
	offset     int
	chunkLimit int
	cfg        sendConfig
	useEnc     bool
	sendPacket func(uint16, []byte)
}

func sendLoop(ls *sendLoopState) error {
	for {
		ls.state.mu.Lock()
		windowFull := len(ls.state.pending) >= WINDOW_SIZE
		allSent := ls.state.allSent
		pendingCount := len(ls.state.pending)
		ls.state.mu.Unlock()

		if allSent && pendingCount == 0 {
			break
		}

		if !allSent && !windowFull {
			end := ls.offset + ls.chunkLimit
			if end > ls.total {
				end = ls.total
			}
			chunk := ls.plainData[ls.offset:end]
			ls.offset = end
			var payload []byte
			if ls.useEnc {
				nonce, ciphertext, err := encryptChunk(ls.cfg.key, chunk, ls.cfg.cipher)
				if err != nil {
					return fmt.Errorf("encryption failed: %v", err)
				}
				payload = append(nonce, ciphertext...)
			} else {
				payload = chunk
			}
			seq := ls.state.nextSeq
			ls.state.nextSeq++
			ls.state.addPending(seq, payload, func(seq uint16) {
				ls.state.retransmit(seq, ls.sendPacket)
			})
			ls.sendPacket(seq, payload)
			if ls.offset >= ls.total {
				ls.state.mu.Lock()
				ls.state.allSent = true
				ls.state.mu.Unlock()
			}
			time.Sleep(ls.cfg.interval)
			continue
		}

		select {
		case seq, ok := <-ls.ackCh:
			if !ok {
				return fmt.Errorf("ACK receiver died")
			}
			ls.state.ackReceived(seq)
		case <-time.After(ls.cfg.timeout):
			ls.state.mu.Lock()
			if len(ls.state.pending) == 0 {
				ls.state.mu.Unlock()
				continue
			}
			if ls.state.allSent {
				ls.state.mu.Unlock()
				fmt.Println("Timeout waiting for ACKs – giving up")
				return fmt.Errorf("transmission incomplete")
			}
			ls.state.mu.Unlock()
		}
	}
	return nil
}

func runSend(cfg sendConfig) error {
	useEncryption := len(cfg.key) > 0
	plainData, total, maxPlain, err := prepareSendData(cfg)
	if err != nil {
		return err
	}

	dest, addr, err := resolveDest(cfg.destHost)
	if err != nil {
		return err
	}

	fd, err := openRawSocket(cfg.timeout)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	state := &senderState{
		pending:    make(map[uint16]*pendingPacket),
		nextSeq:    1,
		windowBase: 1,
		done:       make(chan struct{}),
		timeout:    cfg.timeout,
	}

	sendPacket := func(seq uint16, data []byte) {
		sendChunk(fd, addr, cfg.tunnelID, seq, data)
	}

	ackCh := startAckListener(fd, state, dest, cfg.tunnelID)

	chunkLimit := maxPlain
	if !useEncryption {
		chunkLimit = cfg.chunkSize
	}

	ls := &sendLoopState{
		state:      state,
		ackCh:      ackCh,
		plainData:  plainData,
		total:      total,
		chunkLimit: chunkLimit,
		cfg:        cfg,
		useEnc:     useEncryption,
		sendPacket: sendPacket,
	}

	if err := sendLoop(ls); err != nil {
		close(state.done)
		return err
	}

	close(state.done)
	return nil
}
