package main

import (
	"encoding/binary"
)

func icmpEchoRequest(id uint16, seq uint16, payload []byte) []byte {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint16(hdr[4:6], id)
	binary.BigEndian.PutUint16(hdr[6:8], seq)
	packet := append(hdr, payload...)
	binary.BigEndian.PutUint16(packet[2:4], 0)
	cksum := icmpChecksum(packet)
	binary.BigEndian.PutUint16(packet[2:4], cksum)
	return packet
}

func icmpEchoReply(id uint16, seq uint16, payload []byte) []byte {
	hdr := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(hdr[4:6], id)
	binary.BigEndian.PutUint16(hdr[6:8], seq)
	packet := append(hdr, payload...)
	binary.BigEndian.PutUint16(packet[2:4], 0)
	cksum := icmpChecksum(packet)
	binary.BigEndian.PutUint16(packet[2:4], cksum)
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
