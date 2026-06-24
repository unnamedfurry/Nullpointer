package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

const grpcPort = ":34132"
const binsDir = "/var/www/html/bins"

type BinaryService struct {
	listener net.Listener
}

func StartBinaryService() (*BinaryService, error) {
	ln, err := net.Listen("tcp", grpcPort)
	if err != nil {
		return nil, fmt.Errorf("binary service listen: %w", err)
	}

	bs := &BinaryService{listener: ln}
	go bs.acceptLoop()
	return bs, nil
}

func (bs *BinaryService) acceptLoop() {
	for {
		conn, err := bs.listener.Accept()
		if err != nil {
			continue
		}
		go bs.handleConn(conn)
	}
}

func (bs *BinaryService) handleConn(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}

	// request format: [arch_len:2][arch] (simple, no protobuf for now)
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

func (bs *BinaryService) streamBinary(conn net.Conn, arch string) {
	binPath := filepath.Join(binsDir, "fnbnet."+arch)
	f, err := os.Open(binPath)
	if err != nil {
		// send empty response with total_size=0
		resp := make([]byte, 8)
		binary.BigEndian.PutUint32(resp[0:4], 0) // total_size
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

		// response: [total_size:4][offset:4][data_len:2][data...]
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
}
