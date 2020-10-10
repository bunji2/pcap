package icmp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Header は ICMP の共通ヘッダ
type Header struct {
	Type     uint8
	Code     uint8
	Checksum [2]byte
}

func (h Header) String() (r string) {
	r = fmt.Sprintf("Type: %s(%d)\nCode: %d",
		TypeMessage[h.Type], h.Type, h.Code)
	return
}

// TypeMessage は ICMP パケットのタイプ
var TypeMessage = []string{
	"Echo Reply",              // 0
	"(reserved)",              // 1
	"(reserved)",              // 2
	"Destination Unreachable", // 3
	"Source Quench",           // 4
	"Redirect",                // 5
	"(reserved)",              // 6
	"(reserved)",              // 7
	"Echo Request",            // 8
	"Router Advertisement",    // 9
	"Router Selection",        // 10
	"Time Exceeded",           // 11
	"Parameter Problem",       // 12
	"Timestamp",               // 13
	"Timestamp Reply",         // 14
	"Information Request",     // 15
	"Information Reply",       // 16
	"Address Mask Request",    // 17
	"Address Mask Reply",      // 18
	"(reserved)",              // 19
	"(reserved)",              // 20
	"(reserved)",              // 21
	"(reserved)",              // 22
	"(reserved)",              // 23
	"(reserved)",              // 24
	"(reserved)",              // 25
	"(reserved)",              // 26
	"(reserved)",              // 27
	"(reserved)",              // 28
	"(reserved)",              // 29
	"Traceroute",              // 30

}

// ParseHeader ヘッダをパースする
func ParseHeader(bb []byte) (r Header, err error) {
	err = binary.Read(bytes.NewReader(bb), binary.BigEndian, &r)
	return
}

// Do パケットを処理する
func (h Header) Do(process func(Header, []byte) error, payload []byte) error {
	if process == nil {
		return nil
	}
	return process(h, payload)
}
