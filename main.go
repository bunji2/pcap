package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"./arp"
	"./ether"
	"./icmp"
	"./ip"
	"./tcp"
	"./udp"
)

const (
	usageFmt  = "Usage: %s pcap_file\n"
	paramFile = "param.json"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usageFmt, os.Args[0])
		return 1
	}
	err := loadParam(paramFile)
	if err != nil {
		return 2
	}

	err = processPcapFile(os.Args[1])

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	return 0
}

/*
func xprocessPcapFile(filePath string) (err error) {
	var f *os.File
	f, err = os.Open(filePath)
	if err != nil {
		return
	}
	defer f.Close()

	// PCAP ファイルのヘッダ
	var ph PcapHeader
	ph, err = readPcapHeader(f)
	if err != nil {
		return
	}
	//fmt.Println("[PCAP]")
	//fmt.Println(ph.String())
	if len(param.PCAP) > 0 {
		processPcap(ph)
	}

	if ph.Network != 1 {
		err = fmt.Errorf("unknown network(%d)", ph.Network)
		return
	}

	//i := 0
	for i := 0; true; i++ {
		var prh PcapRecHeader
		prh, err = readPcapRecHeader(f)
		if err != nil {
			break
		}
		//fmt.Println("--------")
		//fmt.Printf("[Record#%d]\n", i)
		//fmt.Println(prh.String())
		if len(param.Record) > 0 {
			processRecord(prh, i)
		}
		if prh.InclLen < 1 {
			continue
		}

		// 読み飛ばす
		//f.Seek(int64(prh.InclLen), 1)
		//continue

		// Ether フレーム全体の読み出し
		var bb []byte
		bb, err = readBytes(f, int(prh.InclLen))
		if err != nil {
			break
		}

		// Ether フレームヘッダの取得
		var eh ether.Header
		eh, err = ether.ParseHeader(bb[0:14])
		if err != nil {
			break
		}
		if len(param.Ether) > 0 {
			processEther(eh, nil, i)
		}

		// IP パケットヘッダの取得
		var ih ip.Header
		ih, err = ip.ParseHeader(bb[14:])
		if err != nil {
			break
		}
		if ih.Version != 4 {
			err = fmt.Errorf("not IPv4")
			return
		}

		offset := 14 + ih.HeaderLen // IPv4 パケットのペイロードへのオフセット

		if len(param.IP) > 0 {
			processIP(ih, bb[offset:], i)
		}

		switch ih.Protocol {
		case 1: // ICMP
			var h icmp.Header
			h, err = icmp.ParseHeader(bb[offset : offset+4])
			if err != nil {
				break
			}
			if len(param.ICMP) > 0 {
				processICMP(h, bb[offset+4:], i)
			}

		case 6: //TCP
			var h tcp.Header
			h, err = tcp.ParseHeader(bb[offset : offset+20])
			if err != nil {
				break
			}
			if len(param.TCP) > 0 {
				processTCP(h, bb[offset+20:], i)
			}

		case 17: //UDP
			var h udp.Header
			h, err = udp.ParseHeader(bb[offset : offset+8])
			if err != nil {
				break
			}
			if len(param.UDP) > 0 {
				processUDP(h, bb[offset+8:], i)
			}

		default:
			// ignore
			processOTHER(i)

		}

		if err != nil {
			break
		}

	}

	if err == io.EOF {
		err = nil
	}

	return
}
*/

func processPcapFile(filePath string) (err error) {
	var f *os.File
	f, err = os.Open(filepath.Clean(filePath))
	if err != nil {
		return
	}
	defer func() {
		e := f.Close()
		if err == nil {
			err = e
		}
	}()

	// PCAP ファイルのヘッダ
	var ph PcapHeader
	ph, err = readPcapHeader(f)
	if err != nil {
		return
	}
	//fmt.Println("[PCAP]")
	//fmt.Println(ph.String())
	if len(param.PCAP) > 0 {
		err = processPcap(ph)
		if err != nil {
			return
		}
	}

	if ph.Network != 1 {
		err = fmt.Errorf("unknown network(%d)", ph.Network)
		return
	}

	for recNo := 0; true; recNo++ {
		var prh PcapRecHeader
		prh, err = readPcapRecHeader(f)
		if err != nil {
			break
		}
		//fmt.Println("--------")
		//fmt.Printf("[Record#%d]\n", i)
		//fmt.Println(prh.String())
		if len(param.Record) > 0 {
			err = processRecord(prh, recNo)
			if err != nil {
				return
			}
		}
		if prh.InclLen < 1 {
			continue
		}

		// 読み飛ばす
		//f.Seek(int64(prh.InclLen), 1)
		//continue

		// Ether フレーム全体の読み出し
		var bb []byte
		bb, err = readBytes(f, int(prh.InclLen))
		if err != nil {
			break
		}

		// Ether フレームヘッダの取得
		var eh ether.Header
		eh, err = ether.ParseHeader(bb[0:14])
		if err != nil {
			break
		}
		if len(param.Ether) > 0 {
			err = processEther(eh, nil, recNo)
			if err != nil {
				return
			}
		}

		// Ethernet フレームワークのペイロードへのオフセット
		offset := 14

		// Ethernet フレームワークヘッダの Type の値で上位プロトコルを判別
		switch eh.Type {
		case 0x0800: // IPv4
			err = processIPPacket(bb[offset:], recNo)
		case 0x0806, 0x8035: // ARP, RARP
			var h arp.Header
			h, err = arp.ParseHeader(bb[offset:])
			if len(param.ARP) > 0 {
				err = processARP(h, bb[offset+h.HeaderLen():], recNo)
			}
		default:
			err = processOTHER(recNo)
		}

		if err != nil {
			break
		}

	}

	if err == io.EOF {
		err = nil
	}

	return
}

func processIPPacket(bb []byte, recNo int) (err error) {
	// IP パケットヘッダの取得
	var ih ip.Header
	//ih, err = ip.ParseHeader(bb[0:20])
	ih, err = ip.ParseHeader(bb)
	if err != nil {
		return
	}
	if ih.Version != 4 {
		err = fmt.Errorf("not IPv4")
		return
	}

	offset := ih.HeaderLen // IPv4 パケットのペイロードへのオフセット

	if len(param.IP) > 0 {
		err = processIP(ih, bb[offset:], recNo)
		if err != nil {
			return
		}
	}

	switch ih.Protocol {
	case 1: // ICMP
		var h icmp.Header
		h, err = icmp.ParseHeader(bb[offset : offset+4])
		if err != nil {
			break
		}
		if len(param.ICMP) > 0 {
			err = processICMP(h, bb[offset+4:], recNo)
		}
	case 6: //TCP
		var h tcp.Header
		h, err = tcp.ParseHeader(bb[offset:])
		if err != nil {
			break
		}
		if len(param.TCP) > 0 {
			err = processTCP(h, bb[offset+h.HeaderLen:], recNo)
		}
	case 17: //UDP
		var h udp.Header
		h, err = udp.ParseHeader(bb[offset : offset+8])
		if err != nil {
			break
		}
		if len(param.UDP) > 0 {
			err = processUDP(h, bb[offset+8:], recNo)
		}
	default:
		// ignore
		err = processOTHER(recNo)
	}

	if err == io.EOF {
		err = nil
	}

	return
}

func readBytes(f io.Reader, len int) (r []byte, err error) {
	buf := make([]byte, len)
	var n int
	n, err = f.Read(buf)
	if err != nil {
		if err == io.EOF {
			err = nil
			return
		}
	}
	if n == 0 {
		return
	}
	r = buf
	return
}

func hex(bb []byte) (r string) {
	for _, b := range bb {
		r += fmt.Sprintf("%02X", b)
	}
	return
}
