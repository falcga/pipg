package main

import (
	"bytes"
	"compress/zlib"
	"io"
	"sort"
	"sync"
	"time"
)

type reassembly struct {
	mu        sync.Mutex
	chunks    map[uint16][]byte
	lastSeen  time.Time
	completed bool
}

func newReassembly() *reassembly {
	return &reassembly{
		chunks:   make(map[uint16][]byte),
		lastSeen: time.Now(),
	}
}

func (r *reassembly) add(seq uint16, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.completed {
		return
	}
	if _, ok := r.chunks[seq]; !ok {
		r.chunks[seq] = data
	}
	r.lastSeen = time.Now()
}

func (r *reassembly) assemble() ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.completed || len(r.chunks) == 0 {
		return nil, nil
	}
	seqs := make([]uint16, 0, len(r.chunks))
	for seq := range r.chunks {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for i, seq := range seqs {
		if uint16(i+1) != seq {
			return nil, nil
		}
	}
	var full []byte
	for _, seq := range seqs {
		full = append(full, r.chunks[seq]...)
	}
	r.completed = true
	zr, err := zlib.NewReader(bytes.NewReader(full))
	if err != nil {
		return full, nil
	}
	defer zr.Close()
	decompressed, err := io.ReadAll(zr)
	if err != nil {
		return full, nil
	}
	return decompressed, nil
}
