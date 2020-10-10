package udp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Header UDPパケットのヘッダ
type Header struct {
	Src      uint16
	Dst      uint16
	Len      uint16
	Checksum uint16
}

// String は文字列にする関数
func (h Header) String() string {
	return fmt.Sprintf("Src: %d\nDst: %d\nLen: %d",
		h.Src, h.Dst, h.Len)
}

/*
func readHeader(f io.Reader) (r Header, err error) {
	var bb []byte
	bb, err = readBytes(f, 8) // 8 = UDPヘッダの固定サイズ。
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
func (h Header) Do(process func(Header, []byte) error, payload []byte) error {
	if process == nil {
		return nil
	}
	return process(h, payload)
}
