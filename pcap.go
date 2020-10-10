package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// PcapHeader は PCAP ファイルのヘッダのデータ
type PcapHeader struct {
	MagicNumber  [4]byte
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     uint32
	SigFigs      uint32
	SnapLen      uint32
	Network      uint32 // 1 when Ethernet
}

func (ph PcapHeader) String() string {
	return fmt.Sprintf("MagicNumber: %s\nVersion: %d.%d\nNetwork:%d", hex(ph.MagicNumber[0:]), ph.VersionMajor, ph.VersionMinor, ph.Network)
}

func readPcapHeader(f io.Reader) (r PcapHeader, err error) {
	var bb []byte
	bb, err = readBytes(f, 24)
	if err != nil {
		return
	}
	err = binary.Read(bytes.NewReader(bb), binary.LittleEndian, &r) // LittleEndian にすること
	return
}

// PcapRecHeader は PCAP ファイルのレコードヘッダのデータ
type PcapRecHeader struct {
	TsSec   uint32
	TsUSec  uint32
	InclLen uint32
	OrigLen uint32
}

func (prh PcapRecHeader) String() string {
	return fmt.Sprintf("TimeStamp: %s\nLen:%d", time.Unix(int64(prh.TsSec), int64(prh.TsUSec*1000)), prh.InclLen)
}
func readPcapRecHeader(f io.Reader) (r PcapRecHeader, err error) {
	var bb []byte
	bb, err = readBytes(f, 16)
	if err != nil {
		return
	}
	//fmt.Println("#", hexBytes(bb))
	err = binary.Read(bytes.NewReader(bb), binary.LittleEndian, &r) // LittleEndian にすること
	return
}
