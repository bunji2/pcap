package main

import (
	"fmt"
	"os"
	"time"

	"./ether"
	"./icmp"
	"./ip"
	"./tcp"
	"./udp"
)

func processPcap(h PcapHeader) (err error) {
	for _, tag := range param.PCAP {
		var value string
		switch tag {
		case "MagicNumber":
			value = hex(h.MagicNumber[0:])
		case "Version":
			value = fmt.Sprintf("%d.%d",
				h.VersionMajor, h.VersionMinor)
		case "Network":
			value = fmt.Sprintf("%d", h.Network)
		}
		fmt.Printf("PCAP.%s=%s\n", tag, value)
	}
	return
}

func processRecord(h PcapRecHeader, recNo int) (err error) {

	for _, tag := range param.Record {
		var value string
		switch tag {
		case "TS":
			value = time.Unix(int64(h.TsSec), int64(h.TsUSec*1000)).String()
		case "InclLen":
			value = fmt.Sprintf("%d", h.InclLen)
		}
		fmt.Printf("%d.%s=%s\n", recNo, tag, value)
	}
	return
}

func processEther(h ether.Header, payload []byte, recNo int) (err error) {
	//fmt.Println("[Ether]")
	for _, tag := range param.Ether {
		var value string
		switch tag {
		case "Src":
			value = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
				h.Src[0], h.Src[1], h.Src[2], h.Src[3], h.Src[4], h.Src[5])
		case "Dst":
			value = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
				h.Dst[0], h.Dst[1], h.Dst[2], h.Dst[3], h.Dst[4], h.Dst[5])
		case "Len":
			value = fmt.Sprintf("%d", h.Len)
		}
		fmt.Printf("%d.Ether.%s=%s\n", recNo, tag, value)
	}
	//fmt.Println(h.String())
	return
}

func processIP(h ip.Header, payload []byte, recNo int) (err error) {
	//fmt.Println("[IPv4]")
	for _, tag := range param.IP {
		var value string
		switch tag {
		case "ToS":
			value = fmt.Sprintf("%d", h.ToS)
		case "Identifier":
			value = fmt.Sprintf("%d", h.Identifier)
		case "FragmentOffset":
			value = fmt.Sprintf("%d", h.FragmentOffset)
		case "TTL":
			value = fmt.Sprintf("%d", h.TTL)
		case "Protocol":
			value = fmt.Sprintf("%d", h.Protocol)
		case "HeaderChecksum":
			value = fmt.Sprintf("%d", h.HeaderChecksum)
		case "Version":
			value = fmt.Sprintf("%d", h.Ver())
		case "HeaderLen":
			value = fmt.Sprintf("%d", h.HLen())
		case "Src":
			value = fmt.Sprintf("%d.%d.%d.%d", h.Src[0], h.Src[1], h.Src[2], h.Src[3])
		case "Dst":
			value = fmt.Sprintf("%d.%d.%d.%d", h.Dst[0], h.Dst[1], h.Dst[2], h.Dst[3])
		}
		fmt.Printf("%d.IP.%s=%s\n", recNo, tag, value)
	}
	//fmt.Println(h.String())
	return
}

/*
	Src        uint16
	Dst        uint16
	SeqNo      uint32
	AckNo      uint32
	DataOffset uint8
	Flags      uint8
	WindowSize uint16
	Checksum   uint16
	Urgent     uint16
*/

func processTCP(h tcp.Header, payload []byte, recNo int) (err error) {
	for _, tag := range param.TCP {
		var value string
		switch tag {
		case "Src":
			value = fmt.Sprintf("%d", h.Src)
		case "Dst":
			value = fmt.Sprintf("%d", h.Dst)
		case "SeqNo":
			value = fmt.Sprintf("%d", h.SeqNo)
		case "AckNo":
			value = fmt.Sprintf("%d", h.AckNo)
		case "DataOffset":
			dataOffset := ((h.DataOffset) >> 4) * 4
			value = fmt.Sprintf("%d", dataOffset)
		case "WindowSize":
			value = fmt.Sprintf("%d", h.WindowSize)
		case "Checksum":
			value = fmt.Sprintf("%d", h.Checksum)
		case "Urgent":
			value = fmt.Sprintf("%d", h.Urgent)
		case "URG":
			value = fmt.Sprintf("%d", (h.Flags&0x20)>>5)
		case "ACK":
			value = fmt.Sprintf("%d", (h.Flags&0x10)>>4)
		case "PSH":
			value = fmt.Sprintf("%d", (h.Flags&0x08)>>3)
		case "RST":
			value = fmt.Sprintf("%d", (h.Flags&0x04)>>2)
		case "SYN":
			value = fmt.Sprintf("%d", (h.Flags&0x02)>>1)
		case "FIN":
			value = fmt.Sprintf("%d", h.Flags&0x01)
		case "Options":
			dataOffset := ((h.DataOffset) >> 4) * 4
			value = hex(payload[0 : dataOffset-20])
		case "Payload":
			dataOffset := ((h.DataOffset) >> 4) * 4
			payload = payload[dataOffset-20:]
			till := len(payload)
			if till > 0 {
				postfix := ""
				if till > 16 {
					till = 16
					postfix = "..."
				}
				value = hex(payload)[0:till] + postfix
				err = saveFile(fmt.Sprintf("%d.TCP.%s.dat", recNo, tag), payload)
			}
		}
		fmt.Printf("%d.TCP.%s=%s\n", recNo, tag, value)
	}
	return
}

func processUDP(h udp.Header, payload []byte, recNo int) (err error) {
	for _, tag := range param.UDP {
		var value string
		switch tag {
		case "Src":
			value = fmt.Sprintf("%d", h.Src)
		case "Dst":
			value = fmt.Sprintf("%d", h.Dst)
		case "Len":
			value = fmt.Sprintf("%d", h.Len)
		case "Payload":
			if len(payload) > 0 {
				till := len(payload)
				postfix := ""
				if till > 16 {
					till = 16
					postfix = "..."
				}
				value = hex(payload)[0:till] + postfix
				err = saveFile(fmt.Sprintf("%d.UDP.%s.dat", recNo, tag), payload)
			}
		}
		fmt.Printf("%d.UDP.%s=%s\n", recNo, tag, value)
	}
	return
}

func processICMP(h icmp.Header, payload []byte, recNo int) (err error) {
	for _, tag := range param.ICMP {
		var value string
		switch tag {
		case "Type":
			value = fmt.Sprintf("%d", h.Type)
		case "Code":
			value = fmt.Sprintf("%d", h.Code)
		case "Identifier":
			if h.Type == 0 || h.Type == 8 {
				value = hex(payload[0:2])
			}
		case "Sequence":
			if h.Type == 0 || h.Type == 8 {
				value = hex(payload[2:4])
			}
		case "Payload":
			if len(payload) > 0 {

				if h.Type == 0 || h.Type == 8 {
					payload = payload[4:]
				}
				till := len(payload)
				postfix := ""
				if till > 16 {
					till = 16
					postfix = "..."
				}
				value = hex(payload)[0:till] + postfix
				err = saveFile(fmt.Sprintf("%d.ICMP.%s.dat", recNo, tag), payload)
			}
		}
		fmt.Printf("%d.ICMP.%s=%s\n", recNo, tag, value)
	}

	return
}

func saveFile(filePath string, bb []byte) (err error) {
	var w *os.File
	w, err = os.Create(filePath)
	if err != nil {
		return
	}
	defer w.Close()
	_, err = w.Write(bb)
	return
}

func processOTHER(recNo int) (err error) {
	if param.OTHER {
		fmt.Printf("%d.UnknownPayload\n", recNo)
	}
	return
}
