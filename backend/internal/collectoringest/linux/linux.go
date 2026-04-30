// Package linux converts the data emitted by the ResponseRay Linux collector
// into normalized timeline events. The collector writes a mix of structured
// JSON dumps (live/processes.json, live/packages.json, live/system_info.json)
// and free-text command outputs (live/network_*.txt, live/firewall_*.txt,
// live/journal_*.jsonl, live/last.txt, live/logons_*.txt) plus raw artifact
// files under the artifacts/ tree.
package linux

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// Process is the entry point invoked by collectoringest.Run when the manifest
// platform is "linux". The dirPath argument is the extracted collector output
// root (the directory containing manifest.json, live/, and artifacts/).
func Process(em *core.Emitter, dirPath, ts string) int {
	artifactDir := filepath.Join(dirPath, "artifacts")
	total := 0
	total += processLinuxProcesses(em, dirPath, ts)
	total += processLinuxNetwork(em, dirPath, ts)
	total += processLinuxFirewall(em, dirPath, ts)
	total += processLinuxSystemInfo(em, dirPath, ts)
	total += processLinuxPackages(em, dirPath, ts)
	total += processLinuxUsers(em, artifactDir, ts)
	total += processLinuxLogons(em, dirPath, ts)
	total += processLinuxSSHJournal(em, dirPath)
	total += processLinuxSystemd(em, artifactDir, ts)
	total += processLinuxCron(em, artifactDir, ts)
	total += processLinuxPersistence(em, artifactDir, ts)
	total += processLinuxSSH(em, artifactDir, ts)
	total += processLinuxShellHistory(em, artifactDir, ts)
	// New parsers
	total += processLinuxBrowsers(em, artifactDir, ts)
	total += processLinuxDocker(em, dirPath, ts)
	total += processLinuxMounts(em, dirPath, ts)
	total += processLinuxKernelModules(em, dirPath, ts)
	total += processLinuxSecurity(em, dirPath, ts)
	total += processLinuxMAC(em, dirPath, ts)
	log.Printf("collectoringest/linux: parsers added %d events", total)
	return total
}

var reSpace = regexp.MustCompile(`\s+`)

// ---------------------------------------------------------------------------
// Processes - parse live/processes.json (array of /proc snapshots).
// ---------------------------------------------------------------------------

// procSnapshot mirrors the shape produced by collector-linux ProcessCollector.
type procSnapshot struct {
	PID                 string `json:"pid"`
	Name                string `json:"name"`
	State               string `json:"state"`
	PPID                string `json:"ppid"`
	UID                 string `json:"uid"`
	GID                 string `json:"gid"`
	Cmdline             string `json:"cmdline"`
	Exe                 string `json:"exe"`
	Cwd                 string `json:"cwd"`
	Root                string `json:"root"`
	Environ             string `json:"environ"`
	CollectionTimestamp string `json:"collection_timestamp"`
}

func processLinuxProcesses(em *core.Emitter, dirPath, ts string) int {
	p := filepath.Join(dirPath, "live", "processes.json")
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	var procs []procSnapshot
	if err := json.Unmarshal(data, &procs); err != nil {
		return 0
	}
	added := 0
	for _, ps := range procs {
		if ps.PID == "" {
			continue
		}
		// status's Uid line is space-separated: "real effective saved fs". Take the first.
		uid := ps.UID
		if i := strings.IndexAny(uid, " \t"); i > 0 {
			uid = uid[:i]
		}
		gid := ps.GID
		if i := strings.IndexAny(gid, " \t"); i > 0 {
			gid = gid[:i]
		}

		display := ps.Cmdline
		if display == "" {
			display = ps.Exe
		}
		if display == "" {
			display = ps.Name
		}
		if len(display) > 200 {
			display = display[:200] + "..."
		}
		base := filepath.Base(ps.Exe)
		if base == "" || base == "." {
			base = ps.Name
		}
		msg := fmt.Sprintf("Running: %s (PID:%s) %s", base, ps.PID, display)

		t := ts
		if ps.CollectionTimestamp != "" {
			t = ps.CollectionTimestamp
		}
		attrs := map[string]interface{}{
			"process_name": base,
			"process_path": ps.Exe,
			"command_line": ps.Cmdline,
			"pid":          ps.PID,
			"ppid":         ps.PPID,
			"uid":          uid,
			"gid":          gid,
			"state":        ps.State,
			"cwd":          ps.Cwd,
			"root":         ps.Root,
			"name":         ps.Name,
		}
		if em.AddEvent(t, "Collection Time (Process Running)", msg, "running_process",
			"RR-Linux", "ResponseRay Linux Collector - /proc snapshot",
			"linux:process:running", attrs) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Network - parse live/network_ss_-tunap.txt and live/network_netstat_an.txt.
// ---------------------------------------------------------------------------

// `ss -tunap` output:
//
//	Netid State  Recv-Q Send-Q Local Address:Port           Peer Address:Port    Process
//	tcp   LISTEN 0      128    0.0.0.0:22                   0.0.0.0:*            users:(("sshd",pid=1234,fd=3))
//	tcp   ESTAB  0      0      192.168.1.5:22               192.168.1.10:54321   users:(("sshd",pid=1235,fd=4))
//	udp   UNCONN 0      0      0.0.0.0:5353                 0.0.0.0:*            users:(("avahi-daemon",pid=900,fd=12))
var (
	reSSPid     = regexp.MustCompile(`pid=(\d+)`)
	reSSProcess = regexp.MustCompile(`"([^"]+)",pid=`)
)

func processLinuxNetwork(em *core.Emitter, dirPath, ts string) int {
	added := 0
	added += parseSSText(em, filepath.Join(dirPath, "live", "network_ss_-tunap.txt"), ts)
	if added > 0 {
		return added
	}
	added += parseLinuxNetstatText(em, filepath.Join(dirPath, "live", "network_netstat_an.txt"), ts)
	return added
}

func parseSSText(em *core.Emitter, path, ts string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if first {
			first = false
			if strings.HasPrefix(t, "Netid") || strings.HasPrefix(t, "State") {
				continue
			}
		}
		fields := reSpace.Split(t, 7)
		if len(fields) < 5 {
			continue
		}
		netid := fields[0]
		state := fields[1]
		local := fields[4]
		peer := ""
		if len(fields) >= 6 {
			peer = fields[5]
		}
		processInfo := ""
		if len(fields) >= 7 {
			processInfo = fields[6]
		}

		localIP, localPort := splitHostPort(local)
		remoteIP, remotePort := splitHostPort(peer)

		pidStr := ""
		procName := ""
		if m := reSSPid.FindStringSubmatch(processInfo); len(m) == 2 {
			pidStr = m[1]
		}
		if m := reSSProcess.FindStringSubmatch(processInfo); len(m) == 2 {
			procName = m[1]
		}

		connType := "establishedConnection"
		var msg string
		switch {
		case netid == "udp" || strings.HasPrefix(netid, "udp"):
			connType = "udpListener"
			msg = fmt.Sprintf("UDP Socket: %s:%s [%s]", localIP, localPort, state)
		case state == "LISTEN":
			connType = "listeningPort"
			msg = fmt.Sprintf("Listening: %s %s:%s", netid, localIP, localPort)
		default:
			msg = fmt.Sprintf("Connected: %s:%s -> %s:%s [%s]", localIP, localPort, remoteIP, remotePort, state)
		}
		if procName != "" {
			msg += " (" + procName
			if pidStr != "" {
				msg += " PID:" + pidStr
			}
			msg += ")"
		}

		attrs := map[string]interface{}{
			"connection_type": connType,
			"protocol":        netid,
			"local_ip":        localIP,
			"local_port":      localPort,
			"remote_ip":       remoteIP,
			"remote_port":     remotePort,
			"state":           state,
			"pid":             pidStr,
			"process_name":    procName,
		}
		if em.AddEvent(ts, "Collection Time (Connection Active)", msg, "active_connection",
			"RR-Linux", "ResponseRay Linux Collector - ss -tunap",
			"linux:network:connection", attrs) {
			added++
		}
	}
	return added
}

// netstat -an output on Linux looks similar to macOS but with "ip:port" instead of "ip.port".
func parseLinuxNetstatText(em *core.Emitter, path, ts string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	startedActive := false
	for scanner.Scan() {
		line := scanner.Text()
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if !startedActive {
			if strings.HasPrefix(t, "Proto") {
				startedActive = true
			}
			continue
		}
		if strings.HasPrefix(t, "Active") || strings.HasPrefix(t, "Routing") {
			break
		}
		fields := reSpace.Split(t, -1)
		if len(fields) < 4 {
			continue
		}
		proto := fields[0]
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}
		local := fields[3]
		remote := ""
		state := ""
		if len(fields) >= 5 {
			remote = fields[4]
		}
		if len(fields) >= 6 {
			state = fields[5]
		}
		localIP, localPort := splitHostPort(local)
		remoteIP, remotePort := splitHostPort(remote)

		connType := "establishedConnection"
		var msg string
		switch {
		case strings.HasPrefix(proto, "udp"):
			connType = "udpListener"
			msg = fmt.Sprintf("UDP Listener: %s:%s", localIP, localPort)
		case state == "LISTEN":
			connType = "listeningPort"
			msg = fmt.Sprintf("Listening: %s %s:%s", proto, localIP, localPort)
		default:
			msg = fmt.Sprintf("Connected: %s:%s -> %s:%s [%s]", localIP, localPort, remoteIP, remotePort, state)
		}

		attrs := map[string]interface{}{
			"connection_type": connType,
			"protocol":        proto,
			"local_ip":        localIP,
			"local_port":      localPort,
			"remote_ip":       remoteIP,
			"remote_port":     remotePort,
			"state":           state,
		}
		if em.AddEvent(ts, "Collection Time (Connection Active)", msg, "active_connection",
			"RR-Linux", "ResponseRay Linux Collector - netstat",
			"linux:network:connection", attrs) {
			added++
		}
	}
	return added
}

// splitHostPort handles "ip:port" and "[ipv6]:port", with "*" / "0.0.0.0" left as-is.
func splitHostPort(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end > 0 {
			ip := s[1:end]
			rest := strings.TrimPrefix(s[end+1:], ":")
			return ip, rest
		}
	}
	if idx := strings.LastIndexByte(s, ':'); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}

// ---------------------------------------------------------------------------
// Firewall - emit one os_config snapshot per ruleset.
// ---------------------------------------------------------------------------

func processLinuxFirewall(em *core.Emitter, dirPath, ts string) int {
	added := 0
	rulesets := []struct {
		file, label string
	}{
		{"firewall_iptables-save.txt", "iptables"},
		{"firewall_ip6tables-save.txt", "ip6tables"},
		{"firewall_nft_list_ruleset.txt", "nftables"},
		{"firewall_firewall-cmd_--list-all-zones.txt", "firewalld"},
		{"firewall_ufw_status_verbose.txt", "ufw"},
	}
	for _, r := range rulesets {
		path := filepath.Join(dirPath, "live", r.file)
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			continue
		}
		body := strings.TrimSpace(string(data))
		if body == "" {
			continue
		}
		// Emit one summary event for the ruleset.
		preview := oneLine(body)
		msg := fmt.Sprintf("%s ruleset captured (%d bytes): %s", r.label, len(body), preview)
		if em.AddEvent(ts, "Collection Time (Firewall Rule)", msg, "firewall_rule",
			"RR-Linux", "ResponseRay Linux Collector - "+r.label,
			"linux:firewall:ruleset", map[string]interface{}{
				"setting": r.label,
				"group":   "Firewall",
				"detail":  body,
			}) {
			added++
		}
		// Per-rule events for iptables-save / ip6tables-save -- one per "-A CHAIN" line.
		if r.label == "iptables" || r.label == "ip6tables" {
			scanner := bufio.NewScanner(strings.NewReader(body))
			scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if !strings.HasPrefix(line, "-A ") {
					continue
				}
				display := line
				if len(display) > 200 {
					display = display[:200] + "..."
				}
				if em.AddEvent(ts, "Collection Time (Firewall Rule)",
					fmt.Sprintf("%s rule: %s", r.label, display),
					"firewall_rule",
					"RR-Linux", "ResponseRay Linux Collector - "+r.label,
					"linux:firewall:rule", map[string]interface{}{
						"setting": r.label,
						"rule":    line,
					}) {
					added++
				}
			}
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// System info - hostname, kernel, uname, timedatectl from system_info.json.
// ---------------------------------------------------------------------------

func processLinuxSystemInfo(em *core.Emitter, dirPath, ts string) int {
	p := filepath.Join(dirPath, "live", "system_info.json")
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	var bag map[string]interface{}
	if err := json.Unmarshal(data, &bag); err != nil {
		return 0
	}
	added := 0
	pairs := []struct{ key, label, group string }{
		{"uname_-a", "Kernel", "System"},
		{"uptime", "Uptime", "System"},
		{"timedatectl", "TimeDate", "System"},
		{"locale", "Locale", "System"},
		{"who_-a", "LoggedUsers", "System"},
		{"hostname", "Hostname", "System"},
	}
	for _, pp := range pairs {
		raw, ok := bag[pp.key]
		if !ok {
			continue
		}
		v, _ := raw.(string)
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		val := oneLine(v)
		msg := fmt.Sprintf("System: %s = %s", pp.label, val)
		if em.AddEvent(ts, "Collection Time (OS Configuration)", msg, "os_config",
			"RR-Linux", "ResponseRay Linux Collector - SystemInfo",
			"linux:os:config_setting", map[string]interface{}{
				"setting": pp.label,
				"value":   val,
				"group":   pp.group,
				"detail":  v,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Packages - parse live/packages.json (one block per manager).
// ---------------------------------------------------------------------------

type pkgManagerBlock struct {
	Manager string `json:"manager"`
	Raw     string `json:"raw"`
	Count   int    `json:"count"`
	Error   string `json:"error,omitempty"`
}

func processLinuxPackages(em *core.Emitter, dirPath, ts string) int {
	p := filepath.Join(dirPath, "live", "packages.json")
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	var bag struct {
		Managers []pkgManagerBlock `json:"managers"`
	}
	if err := json.Unmarshal(data, &bag); err != nil {
		return 0
	}
	added := 0
	for _, mgr := range bag.Managers {
		if strings.TrimSpace(mgr.Raw) == "" {
			continue
		}
		switch mgr.Manager {
		case "dpkg":
			added += parseDpkgList(em, mgr.Raw, ts)
		case "rpm":
			added += parseRpmList(em, mgr.Raw, ts)
		case "pacman":
			added += parseSimplePackageList(em, mgr.Raw, ts, "pacman", "linux:pkg:pacman")
		case "snap":
			added += parseSnapList(em, mgr.Raw, ts)
		case "apk":
			added += parseSimplePackageList(em, mgr.Raw, ts, "apk", "linux:pkg:apk")
		case "flatpak":
			added += parseSimplePackageList(em, mgr.Raw, ts, "flatpak", "linux:pkg:flatpak")
		}
	}
	return added
}

// dpkg-query output: "Package\tVersion\tArchitecture\tStatus".
func parseDpkgList(em *core.Emitter, raw, ts string) int {
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t == "" {
			continue
		}
		fields := strings.Split(t, "\t")
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		version := fields[1]
		arch := ""
		status := ""
		if len(fields) >= 3 {
			arch = fields[2]
		}
		if len(fields) >= 4 {
			status = fields[3]
		}
		if !strings.Contains(status, "installed") {
			continue
		}
		msg := fmt.Sprintf("Installed Package (dpkg): %s v%s [%s]", name, version, arch)
		if em.AddEvent(ts, "Collection Time (Program Installed)", msg, "installed_program",
			"RR-Linux", "ResponseRay Linux Collector - dpkg",
			"linux:pkg:dpkg", map[string]interface{}{
				"program_name": name,
				"version":      version,
				"architecture": arch,
				"status":       status,
				"source":       "dpkg",
			}) {
			added++
		}
	}
	return added
}

// rpm -qa output: "NAME\tVERSION-RELEASE\tARCH\tINSTALLTIME\tVENDOR".
func parseRpmList(em *core.Emitter, raw, ts string) int {
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t == "" {
			continue
		}
		fields := strings.Split(t, "\t")
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		version := fields[1]
		arch := ""
		install := ""
		vendor := ""
		if len(fields) >= 3 {
			arch = fields[2]
		}
		if len(fields) >= 4 {
			install = fields[3]
		}
		if len(fields) >= 5 {
			vendor = fields[4]
		}
		msg := fmt.Sprintf("Installed Package (rpm): %s v%s [%s]", name, version, arch)
		if em.AddEvent(ts, "Collection Time (Program Installed)", msg, "installed_program",
			"RR-Linux", "ResponseRay Linux Collector - rpm",
			"linux:pkg:rpm", map[string]interface{}{
				"program_name": name,
				"version":      version,
				"architecture": arch,
				"install_time": install,
				"vendor":       vendor,
				"source":       "rpm",
			}) {
			added++
		}
	}
	return added
}

// pacman -Q / apk info / flatpak list: one item per line, first whitespace-token = name.
func parseSimplePackageList(em *core.Emitter, raw, ts, manager, dataType string) int {
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t == "" {
			continue
		}
		fields := strings.Fields(t)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		version := ""
		if len(fields) >= 2 {
			version = fields[1]
		}
		msg := fmt.Sprintf("Installed Package (%s): %s %s", manager, name, version)
		if em.AddEvent(ts, "Collection Time (Program Installed)", msg, "installed_program",
			"RR-Linux", "ResponseRay Linux Collector - "+manager,
			dataType, map[string]interface{}{
				"program_name": name,
				"version":      version,
				"source":       manager,
			}) {
			added++
		}
	}
	return added
}

// snap list output: "Name Version Rev Tracking Publisher Notes".
func parseSnapList(em *core.Emitter, raw, ts string) int {
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(raw))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	first := true
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t == "" {
			continue
		}
		if first {
			first = false
			if strings.HasPrefix(t, "Name ") || strings.HasPrefix(t, "Name\t") {
				continue
			}
		}
		fields := strings.Fields(t)
		if len(fields) < 2 {
			continue
		}
		name := fields[0]
		version := fields[1]
		msg := fmt.Sprintf("Installed Package (snap): %s v%s", name, version)
		if em.AddEvent(ts, "Collection Time (Program Installed)", msg, "installed_program",
			"RR-Linux", "ResponseRay Linux Collector - snap",
			"linux:pkg:snap", map[string]interface{}{
				"program_name": name,
				"version":      version,
				"source":       "snap",
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Users - parse artifacts/users/etc/passwd and emit one account per row.
// ---------------------------------------------------------------------------

func processLinuxUsers(em *core.Emitter, artifactDir, ts string) int {
	p := filepath.Join(artifactDir, "users", "etc", "passwd")
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		t := strings.TrimSpace(scanner.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		fields := strings.SplitN(t, ":", 7)
		if len(fields) < 7 {
			continue
		}
		uname := fields[0]
		uid := fields[2]
		gid := fields[3]
		gecos := fields[4]
		home := fields[5]
		shell := fields[6]
		hidden := false
		if u, err := strconv.Atoi(uid); err == nil && u < 1000 {
			hidden = true
		}
		msg := "User account: " + uname
		if gecos != "" {
			msg += " (" + gecos + ")"
		}
		if hidden {
			msg += " [system]"
		}
		if em.AddEvent(ts, "Account Created/Modified", msg, "account_created",
			"RR-Linux", "ResponseRay Linux Collector - /etc/passwd",
			"linux:user:account", map[string]interface{}{
				"username":    uname,
				"full_name":   gecos,
				"uid":         uid,
				"gid":         gid,
				"home_dir":    home,
				"shell":       shell,
				"system_user": hidden,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Logons - parse `last -Fwx` text output.
// ---------------------------------------------------------------------------

// `last -Fwx` output (one row per login):
//
//	user     pts/0   192.168.1.10   Thu Apr 20 18:00:01 2026 - Thu Apr 20 19:00:00 2026  (00:59)
//	reboot   system boot 6.6.0-1     Mon Apr 17 09:00:00 2026   still running
func processLinuxLogons(em *core.Emitter, dirPath, ts string) int {
	added := 0
	for _, name := range []string{"last", "lastb"} {
		path := filepath.Join(dirPath, "live", "logons_"+name+"_-Fxw.txt")
		// Also try the alt name produced by some collectors.
		if _, err := os.Stat(path); err != nil {
			path = filepath.Join(dirPath, "live", name+".txt")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		etype := "logon_success"
		desc := "Logon Recorded"
		if name == "lastb" {
			etype = "logon_failed"
			desc = "Failed Logon Recorded"
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "wtmp") || strings.HasPrefix(t, "btmp") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			user := fields[0]
			term := fields[1]
			from := fields[2]
			// Day Mon DD HH:MM:SS YYYY -- five tokens
			if len(fields) < 8 {
				continue
			}
			dateStr := strings.Join(fields[3:8], " ")
			dt := parseLastDate(dateStr)
			if dt == "" {
				dt = ts
			}
			msg := fmt.Sprintf("Logon: user=%s tty=%s from=%s", user, term, from)
			if em.AddEvent(dt, desc, msg, etype,
				"RR-Linux", "ResponseRay Linux Collector - "+name,
				"linux:auth:wtmp_entry", map[string]interface{}{
					"username":  user,
					"terminal":  term,
					"source_ip": from,
					"raw_line":  line,
					"source":    name,
				}) {
				added++
			}
		}
	}
	return added
}

// parseLastDate accepts "Day Mon DD HH:MM:SS YYYY" -> ISO 8601 ms UTC.
// We treat the timestamp as local time without zone info; for IR purposes
// rendering it as UTC ms is acceptable since it preserves ordering.
func parseLastDate(s string) string {
	const layout = "Mon Jan 2 15:04:05 2006"
	parsed, err := time.Parse(layout, s)
	if err != nil {
		return ""
	}
	return parsed.UTC().Format("2006-01-02T15:04:05.000") + "Z"
}

// ---------------------------------------------------------------------------
// SSH journal - parse live/journal_sshd.jsonl (one JSON record per line).
// ---------------------------------------------------------------------------

// systemd journal export (-o json) yields a JSON object per line with at least
// __REALTIME_TIMESTAMP (microseconds since epoch), MESSAGE, _PID, _COMM,
// _HOSTNAME, _SYSTEMD_UNIT.
func processLinuxSSHJournal(em *core.Emitter, dirPath string) int {
	p := filepath.Join(dirPath, "live", "journal_sshd.jsonl")
	f, err := os.Open(p)
	if err != nil {
		return 0
	}
	defer f.Close()
	added := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec map[string]interface{}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		message, _ := rec["MESSAGE"].(string)
		if message == "" {
			continue
		}
		usec, _ := rec["__REALTIME_TIMESTAMP"].(string)
		dt := journalUsecToISO(usec)
		if dt == "" {
			continue
		}
		pid, _ := rec["_PID"].(string)
		comm, _ := rec["_COMM"].(string)
		host, _ := rec["_HOSTNAME"].(string)

		etype := "auth_log"
		desc := "SSHD Log Entry"
		switch {
		case strings.Contains(message, "Accepted password") || strings.Contains(message, "Accepted publickey"):
			etype = "logon_success"
			desc = "SSH Logon Success"
		case strings.Contains(message, "Failed password") || strings.Contains(message, "authentication failure") || strings.Contains(message, "Invalid user"):
			etype = "logon_failed"
			desc = "SSH Logon Failed"
		case strings.Contains(message, "session opened") || strings.Contains(message, "session closed"):
			etype = "logon_session"
			desc = "SSH Session Event"
		}
		msg := fmt.Sprintf("sshd[%s]: %s", pid, oneLine(message))
		attrs := map[string]interface{}{
			"message":   message,
			"pid":       pid,
			"unit":      rec["_SYSTEMD_UNIT"],
			"comm":      comm,
			"host_name": host,
			"source":    "journal_sshd",
		}
		if em.AddEvent(dt, desc, msg, etype,
			"RR-Linux", "ResponseRay Linux Collector - journal_sshd",
			"linux:auth:sshd", attrs) {
			added++
		}
	}
	return added
}

// journalUsecToISO converts a __REALTIME_TIMESTAMP string (microseconds since
// epoch) to ISO 8601 ms UTC.
func journalUsecToISO(s string) string {
	if s == "" {
		return ""
	}
	u, err := strconv.ParseInt(s, 10, 64)
	if err != nil || u <= 0 {
		return ""
	}
	sec := u / 1_000_000
	ms := (u % 1_000_000) / 1000
	t := time.Unix(sec, 0).UTC()
	return fmt.Sprintf("%s.%03dZ", t.Format("2006-01-02T15:04:05"), ms)
}

// ---------------------------------------------------------------------------
// Systemd unit files - one startup_item per .service / .timer / .socket.
// ---------------------------------------------------------------------------

func processLinuxSystemd(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "systemd")
	if _, err := os.Stat(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		switch ext {
		case ".service", ".timer", ".socket", ".target", ".path", ".mount", ".automount":
		default:
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		origin := "/" + strings.ReplaceAll(rel, string(filepath.Separator), "/")
		mtime := core.FileMtimeISO(info.ModTime())
		label := strings.TrimSuffix(d.Name(), ext)
		msg := fmt.Sprintf("Systemd %s: %s", strings.TrimPrefix(ext, "."), label)
		attrs := map[string]interface{}{
			"config_type":   "systemd",
			"description":   label,
			"location":      origin,
			"unit_type":     strings.TrimPrefix(ext, "."),
			"file_size":     info.Size(),
			"artifact_path": filepath.ToSlash(filepath.Join("systemd", rel)),
		}
		if em.AddEvent(mtime, "Unit File Modified", msg, "startup_item",
			"RR-Linux", "ResponseRay Linux Collector - systemd",
			"linux:systemd:unit", attrs) {
			added++
		}
		if em.AddEvent(ts, "Collection Time (Service Configuration)", msg, "startup_item",
			"RR-Linux", "ResponseRay Linux Collector - systemd",
			"linux:systemd:unit", core.CopyAttrs(attrs)) {
			added++
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// Cron - one scheduled_task per crontab entry.
// ---------------------------------------------------------------------------

func processLinuxCron(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "cron")
	if _, err := os.Stat(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		origin := "/etc/" + strings.ReplaceAll(rel, string(filepath.Separator), "/")
		mtime := core.FileMtimeISO(info.ModTime())

		// Emit one "file modified" event for the crontab itself.
		msg := fmt.Sprintf("Crontab modified: %s", origin)
		if em.AddEvent(mtime, "Crontab Modified", msg, "scheduled_task",
			"RR-Linux", "ResponseRay Linux Collector - cron",
			"linux:cron:file", map[string]interface{}{
				"config_type":   "cron",
				"location":      origin,
				"file_size":     info.Size(),
				"artifact_path": filepath.ToSlash(filepath.Join("cron", rel)),
			}) {
			added++
		}

		// Skip parsing per-line entries for very large or binary spool files.
		if info.Size() > 1*1024*1024 {
			return nil
		}
		f, ferr := os.Open(path)
		if ferr != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		lineno := 0
		for scanner.Scan() {
			lineno++
			line := strings.TrimRight(scanner.Text(), "\r\n")
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			// Skip MAILTO=, SHELL=, etc.
			if strings.Contains(t, "=") && !strings.ContainsAny(t, " \t") {
				continue
			}
			display := t
			if len(display) > 200 {
				display = display[:200] + "..."
			}
			msg := fmt.Sprintf("Cron entry: %s", display)
			if em.AddEvent(ts, "Collection Time (Scheduled Task)", msg, "scheduled_task",
				"RR-Linux", "ResponseRay Linux Collector - cron",
				"linux:cron:entry", map[string]interface{}{
					"config_type":  "cron",
					"location":     origin,
					"line":         lineno,
					"raw":          t,
					"crontab_file": filepath.Base(origin),
				}) {
				added++
			}
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// Persistence - one startup_item per file under artifacts/persistence.
// ---------------------------------------------------------------------------

func processLinuxPersistence(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "persistence")
	if _, err := os.Stat(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		origin := "/etc/" + strings.ReplaceAll(rel, string(filepath.Separator), "/")
		if strings.HasPrefix(rel, "users"+string(filepath.Separator)) {
			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) >= 3 {
				origin = "/home/" + parts[1] + "/" + strings.Join(parts[2:], "/")
			}
		}

		mtime := core.FileMtimeISO(info.ModTime())
		category := "persistence"
		switch {
		case strings.HasSuffix(rel, "rc.local") || strings.HasSuffix(rel, "ld.so.preload"):
			category = "system_init"
		case strings.HasSuffix(rel, ".bashrc") || strings.HasSuffix(rel, ".zshrc") ||
			strings.HasSuffix(rel, ".profile") || strings.HasSuffix(rel, ".bash_profile") ||
			strings.HasSuffix(rel, ".zprofile"):
			category = "shell_init"
		case strings.Contains(rel, "autostart"):
			category = "desktop_autostart"
		case strings.HasSuffix(rel, ".service") || strings.HasSuffix(rel, ".timer"):
			category = "systemd"
		}

		msg := fmt.Sprintf("Persistence (%s): %s", category, origin)
		attrs := map[string]interface{}{
			"config_type":   "Persistence",
			"description":   filepath.Base(origin),
			"location":      origin,
			"category":      category,
			"file_size":     info.Size(),
			"artifact_path": filepath.ToSlash(filepath.Join("persistence", rel)),
		}
		if em.AddEvent(mtime, "File Modified", msg, "startup_item",
			"RR-Linux", "ResponseRay Linux Collector - Persistence",
			"linux:persistence:file", attrs) {
			added++
		}
		if em.AddEvent(ts, "Collection Time (Persistence Configured)", msg, "startup_item",
			"RR-Linux", "ResponseRay Linux Collector - Persistence",
			"linux:persistence:file", core.CopyAttrs(attrs)) {
			added++
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// SSH - per-user authorized_keys / known_hosts under artifacts/ssh/users/.
// ---------------------------------------------------------------------------

func processLinuxSSH(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "ssh")
	if _, err := os.Stat(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		base := strings.ToLower(d.Name())
		rel, _ := filepath.Rel(root, path)
		user := ""
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) >= 3 && parts[0] == "users" {
			user = parts[1]
		}
		mtime := core.FileMtimeISO(info.ModTime())

		f, ferr := os.Open(path)
		if ferr != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

		switch {
		case base == "authorized_keys" || base == "authorized_keys2":
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				keyType := fields[0]
				keyComment := ""
				if len(fields) >= 3 {
					keyComment = strings.Join(fields[2:], " ")
				}
				msg := fmt.Sprintf("SSH authorized_key: %s %s", keyType, keyComment)
				if user != "" {
					msg += " (user: " + user + ")"
				}
				if em.AddEvent(mtime, "SSH Authorized Key Added", msg, "ssh_authorized_key",
					"RR-Linux", "ResponseRay Linux Collector - SSH",
					"linux:ssh:authorized_key", map[string]interface{}{
						"user_id":     user,
						"key_type":    keyType,
						"key_comment": keyComment,
						"key_data":    fields[1],
					}) {
					added++
				}
			}
		case base == "known_hosts" || base == "known_hosts2":
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				fields := strings.Fields(line)
				if len(fields) < 3 {
					continue
				}
				host := fields[0]
				keyType := fields[1]
				msg := fmt.Sprintf("SSH known_host: %s (%s)", host, keyType)
				if user != "" {
					msg += " (user: " + user + ")"
				}
				if em.AddEvent(mtime, "SSH Known Host Recorded", msg, "ssh_known_host",
					"RR-Linux", "ResponseRay Linux Collector - SSH",
					"linux:ssh:known_host", map[string]interface{}{
						"user_id":  user,
						"host":     host,
						"key_type": keyType,
					}) {
					added++
				}
			}
		case strings.HasPrefix(base, "sshd_config") || strings.HasPrefix(base, "ssh_config") || base == "config":
			msg := fmt.Sprintf("SSH config file: %s", base)
			if user != "" {
				msg += " (user: " + user + ")"
			}
			if em.AddEvent(mtime, "SSH Config Modified", msg, "os_config",
				"RR-Linux", "ResponseRay Linux Collector - SSH",
				"linux:os:config_setting", map[string]interface{}{
					"setting":   "ssh_config",
					"file_name": d.Name(),
					"user_id":   user,
					"file_size": info.Size(),
				}) {
				added++
			}
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// Shell history - one shell_command per line under artifacts/shell_history.
// ---------------------------------------------------------------------------

func processLinuxShellHistory(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "shell_history")
	if _, err := os.Stat(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		f, ferr := os.Open(path)
		if ferr != nil {
			return nil
		}
		defer f.Close()
		rel, _ := filepath.Rel(root, path)
		user := ""
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) >= 2 {
			user = parts[0]
		}
		mtime := core.FileMtimeISO(info.ModTime())
		base := filepath.Base(path)
		isFish := base == "fish_history" || strings.HasSuffix(base, ".fish")

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		lineno := 0
		var fishCmd string
		var fishWhen string
		for scanner.Scan() {
			lineno++
			line := strings.TrimRight(scanner.Text(), "\r\n")
			cmd := strings.TrimSpace(line)
			cmdTS := mtime
			if isFish {
				// fish_history is YAML-ish:
				//   - cmd: ls
				//     when: 1738291293
				if strings.HasPrefix(cmd, "- cmd: ") {
					if fishCmd != "" {
						added += emitFishCmd(em, fishCmd, fishWhen, mtime, user, base, lineno-1)
					}
					fishCmd = strings.TrimPrefix(cmd, "- cmd: ")
					fishWhen = ""
					continue
				}
				if strings.HasPrefix(cmd, "when: ") {
					fishWhen = strings.TrimPrefix(cmd, "when: ")
					continue
				}
				continue
			}
			// zsh extended history: ": <epoch>:<elapsed>;<command>".
			if strings.HasPrefix(cmd, ": ") {
				if semi := strings.Index(cmd, ";"); semi > 0 {
					meta := cmd[2:semi]
					if colon := strings.Index(meta, ":"); colon > 0 {
						epoch := strings.TrimSpace(meta[:colon])
						if e, err := strconv.ParseInt(epoch, 10, 64); err == nil && e > 0 {
							cmdTS = core.EpochToISO(e)
						}
					}
					cmd = cmd[semi+1:]
				}
			}
			if cmd == "" {
				continue
			}
			added += emitShellCmd(em, cmd, cmdTS, user, base, lineno)
		}
		if isFish && fishCmd != "" {
			added += emitFishCmd(em, fishCmd, fishWhen, mtime, user, base, lineno)
		}
		return nil
	})
	return added
}

func emitShellCmd(em *core.Emitter, cmd, cmdTS, user, base string, lineno int) int {
	display := cmd
	if len(display) > 200 {
		display = display[:200] + "..."
	}
	msg := "Shell command: " + display
	if user != "" {
		msg += " (User: " + user + ")"
	}
	if em.AddEvent(cmdTS, "Shell Command Recorded", msg, "shell_command",
		"RR-Linux", "ResponseRay Linux Collector - "+base,
		"linux:shell:history", map[string]interface{}{
			"command":    cmd,
			"user_id":    user,
			"shell_file": base,
			"line":       lineno,
		}) {
		return 1
	}
	return 0
}

func emitFishCmd(em *core.Emitter, cmd, whenStr, fallbackTS, user, base string, lineno int) int {
	cmdTS := fallbackTS
	if e, err := strconv.ParseInt(strings.TrimSpace(whenStr), 10, 64); err == nil && e > 0 {
		cmdTS = core.EpochToISO(e)
	}
	return emitShellCmd(em, cmd, cmdTS, user, base, lineno)
}

// ---------------------------------------------------------------------------
// Helpers (shared with other Linux parsers).
// ---------------------------------------------------------------------------

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}
