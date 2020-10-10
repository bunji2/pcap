package main

import (
	"fmt"
	"io"
	"os"

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

func processPcapFile(filePath string) (err error) {
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
		ih, err = ip.ParseHeader(bb[14:34])
		if err != nil {
			break
		}
		if ih.Ver() != 4 {
			err = fmt.Errorf("not IPv4")
			return
		}

		if len(param.IP) > 0 {
			processIP(ih, bb[34:], i)
		}

		offset := 14 + ih.HLen() // IPv4 パケットのペイロードへのオフセット

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
