package ether

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Header は Ether フレームのヘッダ
type Header struct {
	Src [6]byte
	Dst [6]byte
	Len uint16
}

// String は文字列にする関数
func (eh Header) String() string {
	return fmt.Sprintf("Src: %02x:%02x:%02x:%02x:%02x:%02x\nDst: %02x:%02x:%02x:%02x:%02x:%02x",
		eh.Src[0], eh.Src[1], eh.Src[2], eh.Src[3], eh.Src[4], eh.Src[5],
		eh.Dst[0], eh.Dst[1], eh.Dst[2], eh.Dst[3], eh.Dst[4], eh.Dst[5])
}

/*
func readHeader(f io.Reader) (r Header, err error) {
	var bb []byte
	bb, err = readBytes(f, 16)
	if err != nil {
		return
	}
	//fmt.Println("#", hexBytes(bb))
	err = binary.Read(bytes.NewReader(bb), binary.LittleEndian, &r) // LittleEndian にすること
	return
}
*/

// ParseHeader ヘッダをパースする
func ParseHeader(bb []byte) (r Header, err error) {
	err = binary.Read(bytes.NewReader(bb), binary.BigEndian, &r)
	return
}

// Do パケットを処理する
func (eh Header) Do(process func(Header, []byte) error, payload []byte) error {
	if process == nil {
		return nil
	}
	return process(eh, payload)
}
