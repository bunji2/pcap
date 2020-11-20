package main

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
)

// Param パラメータ
type Param struct {
	PCAP   []string `json:"pcap"`
	Record []string `json:"record"`
	Ether  []string `json:"ether"`
	IP     []string `json:"ip"`
	TCP    []string `json:"tcp"`
	ARP    []string `json:"arp"`
	UDP    []string `json:"udp"`
	ICMP   []string `json:"icmp"`
	OTHER  bool     `json:"other"`
}

var param Param

func loadParam(paramFile string) (err error) {
	// JSONファイル読み込み
	var bb []byte
	bb, err = ioutil.ReadFile(filepath.Clean(paramFile))
	if err != nil {
		// パラメータファイルの読み出しに失敗したときはデフォルト値をセットする。
		param = Param{
			Ether: []string{"Src", "Dst", "Len"},
			//IP:    true,
			//TCP:   true,
			//UDP:   true,
			//ICMP:  true,
			//OTHER: true,
		}
		err = nil
		return
	}
	// JSONデコード
	err = json.Unmarshal(bb, &param)
	return
}
