package main

import (
	"encoding/binary"
	"log"
	"net"
	"time"
)

type Bot struct {
	uid     int
	conn    net.Conn
	version byte
	source  string
}

func NewBot(conn net.Conn, version byte, source string) *Bot {
	return &Bot{-1, conn, version, source}
}

func (this *Bot) Handle() {
	clientList.AddClient(this)
	defer clientList.DelClient(this)
	if debugMode {
		log.Printf("[bot] %s handle start", this.conn.RemoteAddr())
	}

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
	if protoReady() {
		protoEncrypt(buf[2:])
	}
	if debugMode {
		ln := int(binary.BigEndian.Uint16(buf[:2]))
		log.Printf("[bot] %s QueueBuf %d bytes (payload len=%d)", this.conn.RemoteAddr(), len(buf), ln)
	}
	this.conn.Write(buf)
}
