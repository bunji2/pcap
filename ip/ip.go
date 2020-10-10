package ip

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Header IPパケットのヘッダ
type Header struct {
	VerHLen        uint8
	ToS            uint8
	HeaderLen      uint16
	Identifier     uint16
	Flags          uint8
	FragmentOffset uint8
	TTL            uint8
	Protocol       uint8
	HeaderChecksum uint16
	Src            [4]byte
	Dst            [4]byte
	//OptionField    [3]byte
	//Padding        byte
}

// String は文字列にする関数
func (ih Header) String() string {
	version := ih.Ver()
	headerLen := ih.HLen()
	return fmt.Sprintf("Version: %d\nHeaderLen: %d\nProtocol: %d\nSrc: %s\nDst: %s",
		version, headerLen, ih.Protocol, IPv4AddrString(ih.Src), IPv4AddrString(ih.Dst))
}

// Ver バージョン
func (ih Header) Ver() uint16 {
	return uint16(ih.VerHLen >> 4)
}

// HLen ヘッダの長さ
func (ih Header) HLen() uint16 {
	return uint16(ih.VerHLen&0xF) * 4
}

// IPv4AddrString は 4オクテットのバイト列を IP アドレス表記にする関数
func IPv4AddrString(bb [4]byte) (r string) {
	return fmt.Sprintf("%d.%d.%d.%d", bb[0], bb[1], bb[2], bb[3])
}

/*
func readIPv4Header(f io.Reader) (r IPv4Header, err error) {
	var bb []byte
	bb, err = readBytes(f, 20) // 20 = IPヘッダの固定サイズ。可変長のオプションは含めない。
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
func (ih Header) Do(process func(Header, []byte) error, payload []byte) error {
	if process == nil {
		return nil
	}
	return process(ih, payload)
}
