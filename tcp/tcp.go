package tcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Header TCPパケットのヘッダ
type Header struct {
	Src        uint16
	Dst        uint16
	SeqNo      uint32
	AckNo      uint32
	DataOffset uint8
	Flags      uint8
	WindowSize uint16
	Checksum   uint16
	Urgent     uint16
	//OptionPadding    [4]byte
}

// String は文字列にする関数
func (th Header) String() string {
	//urg := (th.Flags & 0x20) >> 5
	ack := (th.Flags & 0x10) >> 4
	psh := (th.Flags & 0x08) >> 3
	rst := (th.Flags & 0x04) >> 2
	syn := (th.Flags & 0x02) >> 1
	fin := th.Flags & 0x01

	return fmt.Sprintf("Src: %d\nDst: %d\nSeqNo: %d\nAckNo: %d\nSYN: %d\nACK: %d\nPSH: %d\nRST: %d\nFIN: %d",
		th.Src, th.Dst, th.SeqNo, th.AckNo, syn, ack, psh, rst, fin)
}

/*
func readHeader(f io.Reader) (r Header, err error) {
	var bb []byte
	bb, err = readBytes(f, 20) // 20 = TCPヘッダの固定サイズ。可変長のオプションは含めない。
	if err != nil {
		return
	}
	//fmt.Println("#", hexBytes(bb))
	err = binary.Read(bytes.NewReader(bb), binary.BigEndian, &r)
	return
}
*/

// ParseHeader ヘッダをパースする
func ParseHeader(bb []byte) (r Header, err error) {
	err = binary.Read(bytes.NewReader(bb), binary.BigEndian, &r)
	return
}

// Do パケットを処理する
func (th Header) Do(process func(Header, []byte) error, payload []byte) error {
	if process == nil {
		return nil
	}
	return process(th, payload)
}
