package collectoringest

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
)

// ProcessMacOS turns the data emitted by the ResponseRay macOS collector into
// timeline events. The macOS collector emits text dumps inside live/*.json
// objects (e.g. ps_auxwwe, lsof, netstat) plus a tree of artifacts (launch
// agents, persistence files, plists, shell history, ssh, etc.) under the
// artifacts/ directory.
//
// The dirPath argument is the extracted collector output root (the directory
// containing manifest.json, live/, and artifacts/).
func ProcessMacOS(em *Emitter, dirPath, ts string) int {
	artifactDir := filepath.Join(dirPath, "artifacts")
	total := 0
	total += processMacProcesses(em, dirPath, ts)
	total += processMacNetwork(em, dirPath, ts)
	total += processMacFirewall(em, dirPath, ts)
	total += processMacBTM(em, dirPath, ts)
	total += processMacLaunchctl(em, dirPath, ts)
	total += processMacLaunchPlists(em, artifactDir, ts)
	total += processMacPersistenceTree(em, artifactDir, ts)
	total += processMacApplications(em, artifactDir, dirPath, ts)
	total += processMacUsers(em, dirPath, ts)
	total += processMacShellHistory(em, artifactDir, ts)
	total += processMacSSH(em, artifactDir, ts)
	total += processMacQuarantine(em, artifactDir, ts)
	total += processMacRecentItems(em, artifactDir, ts)
	total += processMacSystemInfo(em, dirPath, ts)
	total += processMacTimeMachine(em, dirPath, ts)
	log.Printf("collectoringest: macOS parsers added %d events", total)
	return total
}

// macLiveBag reads a live/<name>.json file written by the macOS collector.
// The collector emits these files as `{"key1": "<text dump>", ...}` rather
// than arrays of structured records, so we flatten everything to strings.
func macLiveBag(dirPath, filename string) (map[string]string, bool) {
	p := filepath.Join(dirPath, "live", filename)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		switch t := v.(type) {
		case string:
			out[k] = t
		case nil:
			out[k] = ""
		default:
			b, _ := json.Marshal(t)
			out[k] = string(b)
		}
	}
	return out, true
}

var reSpace = regexp.MustCompile(`\s+`)

// ---------------------------------------------------------------------------
// Processes - parse the ps_auxwwe text dump into running_process events.
// ---------------------------------------------------------------------------

// processMacProcesses parses the `ps auxwwe` block and emits one
// running_process event per process.
//
// `ps auxwwe` columns: USER PID %CPU %MEM VSZ RSS TT STAT STARTED TIME COMMAND
func processMacProcesses(em *Emitter, dirPath, ts string) int {
	bag, ok := macLiveBag(dirPath, "processes.json")
	if !ok {
		return 0
	}
	body := bag["ps_auxwwe"]
	if body == "" {
		return 0
	}

	added := 0
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			if strings.HasPrefix(line, "USER") {
				continue
			}
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := reSpace.Split(strings.TrimLeft(line, " "), 11)
		if len(fields) < 11 {
			continue
		}
		user := fields[0]
		pid, _ := strconv.Atoi(fields[1])
		cpu := fields[2]
		mem := fields[3]
		vsz := fields[4]
		rss := fields[5]
		tt := fields[6]
		stat := fields[7]
		started := fields[8]
		cputime := fields[9]
		cmd := fields[10]

		if pid == 0 {
			continue
		}

		// Some commands are extremely long because they include env vars; keep
		// the executable + first ~120 chars in the message and store the full
		// line as command_line.
		exe := cmd
		if i := strings.IndexByte(exe, ' '); i > 0 {
			exe = exe[:i]
		}
		display := cmd
		if len(display) > 120 {
			display = display[:120] + "..."
		}
		msg := fmt.Sprintf("Running: %s (PID:%d) %s", filepath.Base(exe), pid, display)

		attrs := map[string]interface{}{
			"process_name": filepath.Base(exe),
			"process_path": exe,
			"command_line": cmd,
			"pid":          fmt.Sprint(pid),
			"user_id":      user,
			"cpu_percent":  cpu,
			"mem_percent":  mem,
			"vsz_kb":       vsz,
			"rss_kb":       rss,
			"tty":          tt,
			"stat":         stat,
			"started":      started,
			"cpu_time":     cputime,
		}
		if em.AddEvent(ts, "Collection Time (Process Running)", msg, "running_process",
			"RR-MacOS", "ResponseRay macOS Collector - ps auxwwe",
			"darwin:process:running", attrs) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Network - parse netstat -an and lsof -i text dumps.
// ---------------------------------------------------------------------------

func processMacNetwork(em *Emitter, dirPath, ts string) int {
	bag, ok := macLiveBag(dirPath, "network.json")
	if !ok {
		return 0
	}
	added := 0
	added += parseNetstatText(em, bag, ts)
	added += parseLsofINetText(em, bag, ts)
	return added
}

// netstat -an output looks like:
//
//	tcp4       0      0  10.4.0.5.443           54.85.10.2.49431       ESTABLISHED
//	tcp46      0      0  *.443                  *.*                    LISTEN
//	udp4       0      0  10.4.0.5.5353          *.*
func parseNetstatText(em *Emitter, bag map[string]string, ts string) int {
	body := pickFirst(bag, "netstat_-an", "netstat_an")
	if body == "" {
		return 0
	}
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	startedActive := false
	for scanner.Scan() {
		line := scanner.Text()
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if !startedActive {
			if strings.HasPrefix(line, "Proto") {
				startedActive = true
			}
			continue
		}
		// Stop at the next section header (Active Multipath, Routing tables, etc.)
		if strings.HasPrefix(line, "Active") || strings.HasPrefix(line, "Registered") || strings.HasPrefix(line, "Routing") || strings.HasPrefix(line, "Internal") {
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
		localIP, localPort := splitAddr(local)
		remoteIP, remotePort := splitAddr(remote)

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
			msg = fmt.Sprintf("Connected: %s:%s -> %s:%s", localIP, localPort, remoteIP, remotePort)
		}
		if state != "" {
			msg += " [" + state + "]"
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
			"RR-MacOS", "ResponseRay macOS Collector - netstat",
			"darwin:network:connection", attrs) {
			added++
		}
	}
	return added
}

// lsof -i output adds (PID, process name, user) context per socket, e.g.:
//
//	mDNSRespo   229            _mdnsresponder    7u  IPv4  0xabcd      0t0  UDP *:5353
//	sshd      1234                   root    3u  IPv4  0xefgh      0t0  TCP 10.4.0.5:22 (LISTEN)
//	sshd      1234                   root    4u  IPv4  0xfff0      0t0  TCP 10.4.0.5:22->10.4.0.10:51022 (ESTABLISHED)
func parseLsofINetText(em *Emitter, bag map[string]string, ts string) int {
	body := pickFirst(bag, "lsof_-i", "lsof_i", "lsof")
	if body == "" {
		return 0
	}
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "COMMAND") {
			continue
		}
		fields := reSpace.Split(t, -1)
		if len(fields) < 9 {
			continue
		}
		cmd := fields[0]
		pid, _ := strconv.Atoi(fields[1])
		user := fields[2]
		nodeKind := ""
		var nameStart int
		for i := 4; i < len(fields)-1; i++ {
			if fields[i] == "TCP" || fields[i] == "UDP" {
				nodeKind = fields[i]
				nameStart = i + 1
				break
			}
		}
		if nodeKind == "" || nameStart >= len(fields) {
			continue
		}
		nameAndState := strings.Join(fields[nameStart:], " ")
		state := ""
		name := nameAndState
		if i := strings.LastIndex(nameAndState, "("); i > 0 {
			rest := nameAndState[i+1:]
			if j := strings.IndexByte(rest, ')'); j > 0 {
				state = rest[:j]
				name = strings.TrimSpace(nameAndState[:i])
			}
		}

		var localStr, remoteStr string
		if i := strings.Index(name, "->"); i > 0 {
			localStr = name[:i]
			remoteStr = name[i+2:]
		} else {
			localStr = name
		}
		localIP, localPort := splitAddr(localStr)
		remoteIP, remotePort := splitAddr(remoteStr)

		connType := "establishedConnection"
		var msg string
		switch {
		case nodeKind == "UDP":
			connType = "udpListener"
			msg = fmt.Sprintf("UDP Listener: %s:%s (%s PID:%d %s)", localIP, localPort, cmd, pid, user)
		case state == "LISTEN":
			connType = "listeningPort"
			msg = fmt.Sprintf("Listening: TCP %s:%s (%s PID:%d %s)", localIP, localPort, cmd, pid, user)
		default:
			msg = fmt.Sprintf("Connected: %s:%s -> %s:%s (%s PID:%d %s)", localIP, localPort, remoteIP, remotePort, cmd, pid, user)
		}

		attrs := map[string]interface{}{
			"connection_type": connType,
			"protocol":        nodeKind,
			"local_ip":        localIP,
			"local_port":      localPort,
			"remote_ip":       remoteIP,
			"remote_port":     remotePort,
			"state":           state,
			"pid":             fmt.Sprint(pid),
			"process_name":    cmd,
			"user_id":         user,
		}
		if em.AddEvent(ts, "Collection Time (Connection Active)", msg, "active_connection",
			"RR-MacOS", "ResponseRay macOS Collector - lsof -i",
			"darwin:network:connection", attrs) {
			added++
		}
	}
	return added
}

// splitAddr handles netstat/lsof "ip.port", "[ipv6]:port", "ip:port".
func splitAddr(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" {
		return "", ""
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end > 0 {
			ip := s[1:end]
			rest := s[end+1:]
			rest = strings.TrimPrefix(rest, ":")
			rest = strings.TrimPrefix(rest, ".")
			return ip, rest
		}
	}
	if idx := strings.LastIndexByte(s, '.'); idx > 0 {
		ip := s[:idx]
		port := s[idx+1:]
		ip = strings.Trim(ip, "[]")
		if ip == "*" {
			ip = ""
		}
		return ip, port
	}
	if idx := strings.LastIndexByte(s, ':'); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}

// ---------------------------------------------------------------------------
// Firewall - alf_global / alf_listapps / pfctl.
// ---------------------------------------------------------------------------

func processMacFirewall(em *Emitter, dirPath, ts string) int {
	bag, ok := macLiveBag(dirPath, "firewall.json")
	if !ok {
		return 0
	}
	added := 0
	if g := strings.TrimSpace(bag["alf_global"]); g != "" {
		if em.AddEvent(ts, "Collection Time (OS Configuration)", "Application Firewall: "+oneLine(g), "os_config",
			"RR-MacOS", "ResponseRay macOS Collector - Firewall State",
			"darwin:os:config_setting", map[string]interface{}{
				"setting": "ApplicationLevelFirewall",
				"value":   oneLine(g),
				"group":   "Firewall",
				"detail":  g,
			}) {
			added++
		}
	}
	if apps := bag["alf_listapps"]; apps != "" {
		// alf_listapps text:
		//   Total number of apps = N
		//   1 : /path/to/app
		//        (Allow incoming connections)
		scanner := bufio.NewScanner(strings.NewReader(apps))
		scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		var currentPath string
		for scanner.Scan() {
			line := scanner.Text()
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "Total number") {
				continue
			}
			if i := strings.Index(t, " : "); i > 0 {
				currentPath = strings.TrimSpace(t[i+3:])
				continue
			}
			if currentPath == "" {
				continue
			}
			rule := strings.Trim(t, "()")
			msg := fmt.Sprintf("Firewall rule: %s -- %s", currentPath, rule)
			if em.AddEvent(ts, "Collection Time (Firewall Rule)", msg, "firewall_rule",
				"RR-MacOS", "ResponseRay macOS Collector - Application Firewall",
				"darwin:firewall:rule", map[string]interface{}{
					"setting":  "alf_listapps",
					"app_path": currentPath,
					"rule":     rule,
				}) {
				added++
			}
			currentPath = ""
		}
	}
	for _, key := range []string{"pfctl_rules", "pfctl_info", "pfctl_all"} {
		pf := strings.TrimSpace(bag[key])
		if pf == "" {
			continue
		}
		if em.AddEvent(ts, "Collection Time (OS Configuration)", fmt.Sprintf("pfctl %s captured (%d bytes)", key, len(pf)), "os_config",
			"RR-MacOS", "ResponseRay macOS Collector - PF Firewall",
			"darwin:os:config_setting", map[string]interface{}{
				"setting": key,
				"group":   "Firewall",
				"detail":  pf,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// BTM (Background Task Management) - parse `sfltool dumpbtm` output.
// ---------------------------------------------------------------------------

func processMacBTM(em *Emitter, dirPath, ts string) int {
	p := filepath.Join(dirPath, "live", "sfltool_dumpbtm.txt")
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	added := 0
	for _, b := range splitBTMBlocks(string(data)) {
		fields := parseBTMRecord(b)
		if len(fields) == 0 {
			continue
		}
		name := fields["Name"]
		ident := fields["Identifier"]
		exe := fields["Executable Path"]
		url := fields["URL"]
		typ := fields["Type"]
		disp := fields["Disposition"]
		dev := fields["Developer Name"]

		label := name
		if label == "(null)" || label == "" {
			label = ident
		}
		if label == "" {
			label = exe
		}
		if label == "" {
			continue
		}
		msg := "BTM persistence: " + label
		if typ != "" {
			msg += " (" + typ + ")"
		}
		if disp != "" {
			msg += " [" + disp + "]"
		}

		attrs := map[string]interface{}{
			"config_type": "BackgroundTaskManagement",
			"description": label,
			"details":     exe,
			"location":    url,
			"identifier":  ident,
			"developer":   dev,
			"item_type":   typ,
			"disposition": disp,
		}
		if em.AddEvent(ts, "Collection Time (Persistence Configured)", msg, "startup_item",
			"RR-MacOS", "ResponseRay macOS Collector - sfltool dumpbtm",
			"darwin:btm:item", attrs) {
			added++
		}
	}
	return added
}

// splitBTMBlocks splits sfltool dumpbtm output into individual records by
// detecting lines like " #1:", " #2:", etc.
func splitBTMBlocks(text string) []string {
	lines := strings.Split(text, "\n")
	var blocks []string
	var cur []string
	reHeader := regexp.MustCompile(`^\s*#\d+:\s*$`)
	for _, l := range lines {
		if reHeader.MatchString(l) {
			if len(cur) > 0 {
				blocks = append(blocks, strings.Join(cur, "\n"))
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, l)
	}
	if len(cur) > 0 {
		blocks = append(blocks, strings.Join(cur, "\n"))
	}
	return blocks
}

func parseBTMRecord(block string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		t := strings.TrimSpace(line)
		idx := strings.IndexByte(t, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(t[:idx])
		val := strings.TrimSpace(t[idx+1:])
		if key == "" {
			continue
		}
		switch key {
		case "Name", "Developer Name", "Type", "Flags", "Disposition", "Identifier", "URL", "Executable Path", "Generation", "Parent Identifier", "UUID":
			out[key] = val
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// launchctl list - one row per loaded daemon/agent.
// ---------------------------------------------------------------------------

// processMacLaunchctl parses live/launchctl_list.txt:
//
//	PID	Status	Label
//	-	0	com.apple.SharedFilelistd
//	123	0	com.apple.tendril.agent
func processMacLaunchctl(em *Emitter, dirPath, ts string) int {
	p := filepath.Join(dirPath, "live", "launchctl_list.txt")
	data, err := os.ReadFile(p)
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
			if strings.HasPrefix(t, "PID") {
				continue
			}
		}
		fields := reSpace.Split(t, 3)
		if len(fields) < 3 {
			continue
		}
		pidStr := fields[0]
		statusStr := fields[1]
		label := fields[2]
		if label == "" {
			continue
		}

		state := "loaded"
		if pidStr != "-" && pidStr != "" {
			state = "running"
		}
		if statusStr != "0" && statusStr != "-" && statusStr != "" {
			state = "exited(" + statusStr + ")"
		}
		msg := fmt.Sprintf("launchd: %s [%s]", label, state)
		attrs := map[string]interface{}{
			"config_type":  "launchd",
			"description":  label,
			"service_name": label,
			"display_name": label,
			"status":       state,
			"pid":          pidStr,
			"exit_status":  statusStr,
		}
		if em.AddEvent(ts, "Collection Time (Service Configuration)", msg, "startup_item",
			"RR-MacOS", "ResponseRay macOS Collector - launchctl list",
			"darwin:launchd:service", attrs) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Launch agents/daemons - emit one startup_item per .plist file (mtime + ts).
// ---------------------------------------------------------------------------

func processMacLaunchPlists(em *Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "launch")
	if _, err := os.Stat(root); err != nil {
		return 0
	}
	added := 0
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".plist") {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}

		rel, _ := filepath.Rel(root, path)
		// rel will look like "Library/LaunchAgents/com.example.foo.plist" or
		// "users/runneradmin/LaunchAgents/com.example.bar.plist".
		var origin, scope string
		switch {
		case strings.HasPrefix(rel, "users"+string(filepath.Separator)):
			scope = "user"
			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) >= 4 {
				origin = "/Users/" + parts[1] + "/Library/" + strings.Join(parts[2:], "/")
			} else {
				origin = "/" + strings.ReplaceAll(rel, string(filepath.Separator), "/")
			}
		default:
			scope = "system"
			origin = "/" + strings.ReplaceAll(rel, string(filepath.Separator), "/")
		}

		label := strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
		mtime := FileMtimeISO(info.ModTime())

		msg := fmt.Sprintf("LaunchAgent/Daemon plist: %s [%s]", label, scope)
		attrs := map[string]interface{}{
			"config_type":   "LaunchAgentDaemon",
			"description":   label,
			"details":       origin,
			"location":      origin,
			"plist_path":    origin,
			"plist_size":    info.Size(),
			"scope":         scope,
			"label":         label,
			"artifact_path": filepath.ToSlash(filepath.Join("launch", rel)),
		}
		if em.AddEvent(mtime, "Plist Modified", msg, "startup_item",
			"RR-MacOS", "ResponseRay macOS Collector - LaunchAgents/Daemons",
			"darwin:launchd:plist", attrs) {
			added++
		}
		// Also emit at collection time so the persistence shows up on the
		// timeline at the moment of acquisition regardless of mtime.
		if em.AddEvent(ts, "Collection Time (Persistence Configured)", msg, "startup_item",
			"RR-MacOS", "ResponseRay macOS Collector - LaunchAgents/Daemons",
			"darwin:launchd:plist", copyAttrs(attrs)) {
			added++
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// Persistence tree - one event per file under artifacts/persistence.
// ---------------------------------------------------------------------------

func processMacPersistenceTree(em *Emitter, artifactDir, ts string) int {
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
		origin := "/" + strings.ReplaceAll(rel, string(filepath.Separator), "/")
		// Re-translate user paths back to /Users/<name>/<relative>.
		if strings.HasPrefix(rel, "users"+string(filepath.Separator)) {
			parts := strings.Split(rel, string(filepath.Separator))
			if len(parts) >= 3 {
				origin = "/Users/" + parts[1] + "/" + parts[2]
				if len(parts) > 3 {
					origin += "/" + strings.Join(parts[3:], "/")
				}
			}
		}

		mtime := FileMtimeISO(info.ModTime())
		category := "persistence"
		switch {
		case strings.Contains(rel, "Extensions") || strings.Contains(rel, "SystemExtensions"):
			category = "kext_or_systemextension"
		case strings.Contains(rel, "cron") || strings.HasPrefix(rel, "var/at") || strings.Contains(rel, "/cron/tabs"):
			category = "cron"
		case strings.HasSuffix(rel, "rc") || strings.HasSuffix(rel, "profile") ||
			strings.HasSuffix(rel, ".bashrc") || strings.HasSuffix(rel, ".zshrc") ||
			strings.HasSuffix(rel, ".zprofile") || strings.HasSuffix(rel, ".bash_profile") ||
			strings.HasSuffix(rel, "rc.common") || strings.HasSuffix(rel, "rc.local"):
			category = "shell_init"
		case strings.Contains(rel, "loginwindow"):
			category = "login_hooks"
		}

		msg := fmt.Sprintf("Persistence (%s): %s", category, origin)
		attrs := map[string]interface{}{
			"config_type":   "Persistence",
			"description":   filepath.Base(origin),
			"details":       origin,
			"location":      origin,
			"category":      category,
			"file_size":     info.Size(),
			"artifact_path": filepath.ToSlash(filepath.Join("persistence", rel)),
		}
		if em.AddEvent(mtime, "File Modified", msg, "startup_item",
			"RR-MacOS", "ResponseRay macOS Collector - Persistence",
			"darwin:persistence:file", attrs) {
			added++
		}
		if em.AddEvent(ts, "Collection Time (Persistence Configured)", msg, "startup_item",
			"RR-MacOS", "ResponseRay macOS Collector - Persistence",
			"darwin:persistence:file", copyAttrs(attrs)) {
			added++
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// Applications - one installed_program per Info.plist + parse install_history.
// ---------------------------------------------------------------------------

func processMacApplications(em *Emitter, artifactDir, dirPath, ts string) int {
	added := 0

	// 1) Walk the plist tree -- give each Info.plist an installed_program event.
	root := filepath.Join(artifactDir, "applications")
	if _, err := os.Stat(root); err == nil {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.EqualFold(d.Name(), "Info.plist") {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			origin := "/" + strings.ReplaceAll(rel, string(filepath.Separator), "/")

			appName := ""
			parts := strings.Split(rel, string(filepath.Separator))
			for _, p := range parts {
				if strings.HasSuffix(p, ".app") {
					appName = strings.TrimSuffix(p, ".app")
					break
				}
			}
			if appName == "" {
				appName = strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
			}

			mtime := FileMtimeISO(info.ModTime())
			msg := "Installed Application: " + appName
			attrs := map[string]interface{}{
				"program_name":  appName,
				"install_path":  origin,
				"info_plist":    origin,
				"plist_size":    info.Size(),
				"artifact_path": filepath.ToSlash(filepath.Join("applications", rel)),
			}
			if em.AddEvent(mtime, "Application Bundle Modified", msg, "installed_program",
				"RR-MacOS", "ResponseRay macOS Collector - Applications",
				"darwin:application:bundle", attrs) {
				added++
			}
			return nil
		})
	}

	// 2) Parse install_history text dump for "Install Date:" lines.
	if bag, ok := macLiveBag(dirPath, "applications.json"); ok {
		ih := bag["install_history"]
		if ih == "" {
			ih = bag["installhistory"]
		}
		if ih != "" {
			added += parseInstallHistory(em, ih, ts)
		}
		// Also enqueue pkgutil --pkgs as installed_program rows.
		if pkgs := strings.TrimSpace(bag["pkgutil_pkgs"]); pkgs != "" {
			scanner := bufio.NewScanner(strings.NewReader(pkgs))
			scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
			for scanner.Scan() {
				name := strings.TrimSpace(scanner.Text())
				if name == "" {
					continue
				}
				if em.AddEvent(ts, "Collection Time (Package Installed)", "pkgutil package: "+name,
					"installed_program", "RR-MacOS", "ResponseRay macOS Collector - pkgutil",
					"darwin:pkg:pkgutil", map[string]interface{}{
						"program_name": name,
						"package_id":   name,
						"source":       "pkgutil",
					}) {
					added++
				}
			}
		}
	}
	return added
}

// parseInstallHistory parses macOS `system_profiler SPInstallHistoryDataType`
// text output. The format is:
//
//	Installations:
//
//	    macOS 15.3.1:
//	      Version: 15.3.1
//	      Source: Apple
//	      Install Date: 5/8/25, 4:14 AM
//
// "Install Date" uses the device's locale, so we accept m/d/yy[yy], h:mm a.
var reInstallDate = regexp.MustCompile(`^(\d{1,2})/(\d{1,2})/(\d{2,4}),\s*(\d{1,2}):(\d{2})\s*(AM|PM)?`)

func parseInstallHistory(em *Emitter, body, fallbackTS string) int {
	added := 0
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	var name, version, source, installDate string
	flush := func() {
		if name == "" {
			return
		}
		ts := parseInstallDate(installDate)
		tsDesc := "Program Install Date"
		if ts == "" {
			ts = fallbackTS
			tsDesc = "Collection Time (Program Installed)"
		}
		msg := "Installed Program: " + name
		if version != "" {
			msg += " v" + version
		}
		if source != "" {
			msg += " (" + source + ")"
		}
		if em.AddEvent(ts, tsDesc, msg, "installed_program",
			"RR-MacOS", "ResponseRay macOS Collector - InstallHistory",
			"darwin:install_history:entry", map[string]interface{}{
				"program_name": name,
				"version":      version,
				"source":       source,
				"install_date": installDate,
			}) {
			added++
		}
		name, version, source, installDate = "", "", "", ""
	}
	for scanner.Scan() {
		line := scanner.Text()
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if t == "Installations:" {
			continue
		}
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") && strings.HasSuffix(t, ":") {
			flush()
			name = strings.TrimSuffix(t, ":")
			continue
		}
		if strings.HasPrefix(line, "      ") {
			if i := strings.Index(t, ":"); i > 0 {
				k := strings.TrimSpace(t[:i])
				v := strings.TrimSpace(t[i+1:])
				switch k {
				case "Version":
					version = v
				case "Source":
					source = v
				case "Install Date":
					installDate = v
				}
			}
		}
	}
	flush()
	return added
}

// parseInstallDate converts a macOS install_history "Install Date" string into
// ISO 8601 ms UTC. Assumes the device locale matches "m/d/yy[yy], h:mm AM/PM".
func parseInstallDate(s string) string {
	m := reInstallDate.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	mm, _ := strconv.Atoi(m[1])
	dd, _ := strconv.Atoi(m[2])
	yy, _ := strconv.Atoi(m[3])
	if yy < 100 {
		yy += 2000
	}
	hh, _ := strconv.Atoi(m[4])
	mn, _ := strconv.Atoi(m[5])
	ampm := strings.ToUpper(m[6])
	if ampm == "PM" && hh < 12 {
		hh += 12
	}
	if ampm == "AM" && hh == 12 {
		hh = 0
	}
	if mm == 0 || dd == 0 {
		return ""
	}
	t := time.Date(yy, time.Month(mm), dd, hh, mn, 0, 0, time.UTC)
	return t.Format("2006-01-02T15:04:05.000") + "Z"
}

// ---------------------------------------------------------------------------
// Users - parse the dscacheutil_users text dump.
// ---------------------------------------------------------------------------

func processMacUsers(em *Emitter, dirPath, ts string) int {
	bag, ok := macLiveBag(dirPath, "users.json")
	if !ok {
		return 0
	}
	body := bag["dscacheutil_users"]
	if body == "" {
		return 0
	}
	added := 0
	current := map[string]string{}
	flush := func() {
		uname := current["name"]
		if uname == "" {
			current = map[string]string{}
			return
		}
		uid := current["uid"]
		shell := current["shell"]
		dir := current["dir"]
		gecos := current["gecos"]
		hidden := false
		if u, err := strconv.Atoi(uid); err == nil && u < 500 {
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
			"RR-MacOS", "ResponseRay macOS Collector - dscacheutil",
			"darwin:user:account", map[string]interface{}{
				"username":    uname,
				"full_name":   gecos,
				"uid":         uid,
				"home_dir":    dir,
				"shell":       shell,
				"system_user": hidden,
			}) {
			added++
		}
		current = map[string]string{}
	}
	scanner := bufio.NewScanner(strings.NewReader(body))
	scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		t := strings.TrimSpace(line)
		if t == "" {
			flush()
			continue
		}
		if i := strings.Index(t, ":"); i > 0 {
			k := strings.TrimSpace(t[:i])
			v := strings.TrimSpace(t[i+1:])
			current[k] = v
		}
	}
	flush()
	return added
}

// ---------------------------------------------------------------------------
// Shell history - emit one event per line under artifacts/shell_history.
// ---------------------------------------------------------------------------

func processMacShellHistory(em *Emitter, artifactDir, ts string) int {
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
		// macOS collector saves shell history at artifacts/shell_history/<user>/<file>.
		user := ""
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) >= 2 {
			user = parts[0]
		}
		mtime := FileMtimeISO(info.ModTime())
		base := filepath.Base(path)

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		lineno := 0
		for scanner.Scan() {
			lineno++
			line := strings.TrimRight(scanner.Text(), "\r\n")
			cmd := strings.TrimSpace(line)
			// zsh extended history: ": <epoch>:<elapsed>;<command>".
			cmdTS := mtime
			if strings.HasPrefix(cmd, ": ") {
				if semi := strings.Index(cmd, ";"); semi > 0 {
					meta := cmd[2:semi]
					if colon := strings.Index(meta, ":"); colon > 0 {
						epoch := strings.TrimSpace(meta[:colon])
						if e, err := strconv.ParseInt(epoch, 10, 64); err == nil && e > 0 {
							cmdTS = EpochToISO(e)
						}
					}
					cmd = cmd[semi+1:]
				}
			}
			if cmd == "" {
				continue
			}
			display := cmd
			if len(display) > 200 {
				display = display[:200] + "..."
			}
			msg := "Shell command: " + display
			if user != "" {
				msg += " (User: " + user + ")"
			}
			if em.AddEvent(cmdTS, "Shell Command Recorded", msg, "shell_command",
				"RR-MacOS", "ResponseRay macOS Collector - "+base,
				"darwin:shell:history", map[string]interface{}{
					"command":    cmd,
					"user_id":    user,
					"shell_file": base,
					"line":       lineno,
				}) {
				added++
			}
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// SSH - authorized_keys / known_hosts / config files.
// ---------------------------------------------------------------------------

func processMacSSH(em *Emitter, artifactDir, ts string) int {
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
		mtime := FileMtimeISO(info.ModTime())

		f, ferr := os.Open(path)
		if ferr != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)

		switch {
		case base == "authorized_keys" || strings.HasPrefix(base, "authorized_keys"):
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
					"RR-MacOS", "ResponseRay macOS Collector - SSH",
					"darwin:ssh:authorized_key", map[string]interface{}{
						"user_id":     user,
						"key_type":    keyType,
						"key_comment": keyComment,
						"key_data":    fields[1],
					}) {
					added++
				}
			}
		case base == "known_hosts":
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
					"RR-MacOS", "ResponseRay macOS Collector - SSH",
					"darwin:ssh:known_host", map[string]interface{}{
						"user_id":  user,
						"host":     host,
						"key_type": keyType,
					}) {
					added++
				}
			}
		case strings.HasPrefix(base, "ssh_config") || strings.HasPrefix(base, "sshd_config") || base == "config":
			msg := fmt.Sprintf("SSH config file: %s", base)
			if user != "" {
				msg += " (user: " + user + ")"
			}
			if em.AddEvent(mtime, "SSH Config Modified", msg, "os_config",
				"RR-MacOS", "ResponseRay macOS Collector - SSH",
				"darwin:os:config_setting", map[string]interface{}{
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
// Quarantine - emit one event per file under artifacts/quarantine.
// ---------------------------------------------------------------------------

func processMacQuarantine(em *Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "quarantine")
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
		mtime := FileMtimeISO(info.ModTime())
		msg := fmt.Sprintf("Quarantine artifact captured: %s", rel)
		if em.AddEvent(mtime, "Quarantine Database Modified", msg, "quarantine_event",
			"RR-MacOS", "ResponseRay macOS Collector - Quarantine",
			"darwin:quarantine:db", map[string]interface{}{
				"file_path":     rel,
				"file_size":     info.Size(),
				"artifact_path": filepath.ToSlash(filepath.Join("quarantine", rel)),
			}) {
			added++
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// Recent items - emit one event per file under artifacts/recent_items.
// ---------------------------------------------------------------------------

func processMacRecentItems(em *Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "recent_items")
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
		user := ""
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) >= 3 && parts[0] == "users" {
			user = parts[1]
		}
		mtime := FileMtimeISO(info.ModTime())
		msg := fmt.Sprintf("Recent items file: %s", filepath.Base(rel))
		if user != "" {
			msg += " (user: " + user + ")"
		}
		if em.AddEvent(mtime, "Recent Items Modified", msg, "file_access",
			"RR-MacOS", "ResponseRay macOS Collector - Recent Items",
			"darwin:recent_items:file", map[string]interface{}{
				"file_path":     rel,
				"file_name":     filepath.Base(rel),
				"file_size":     info.Size(),
				"user_id":       user,
				"artifact_path": filepath.ToSlash(filepath.Join("recent_items", rel)),
			}) {
			added++
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// System info - SIP, Gatekeeper, FileVault, OS version, kernel.
// ---------------------------------------------------------------------------

func processMacSystemInfo(em *Emitter, dirPath, ts string) int {
	bag, ok := macLiveBag(dirPath, "system_info.json")
	if !ok {
		return 0
	}
	added := 0
	pairs := []struct{ key, label, group string }{
		{"csrutil_status", "SIP", "Security"},
		{"gatekeeper_status", "Gatekeeper", "Security"},
		{"filevault_status", "FileVault", "Security"},
		{"sw_vers", "OS Version", "System"},
		{"uname", "Kernel", "System"},
	}
	for _, p := range pairs {
		v := strings.TrimSpace(bag[p.key])
		if v == "" {
			continue
		}
		val := oneLine(v)
		msg := fmt.Sprintf("System: %s = %s", p.label, val)
		if em.AddEvent(ts, "Collection Time (OS Configuration)", msg, "os_config",
			"RR-MacOS", "ResponseRay macOS Collector - SystemInfo",
			"darwin:os:config_setting", map[string]interface{}{
				"setting": p.label,
				"value":   val,
				"group":   p.group,
				"detail":  v,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Time Machine.
// ---------------------------------------------------------------------------

func processMacTimeMachine(em *Emitter, dirPath, ts string) int {
	bag, ok := macLiveBag(dirPath, "timemachine.json")
	if !ok {
		return 0
	}
	added := 0
	for _, key := range []string{"destinationinfo", "latestbackup", "status"} {
		v := strings.TrimSpace(bag[key])
		if v == "" {
			continue
		}
		val := oneLine(v)
		msg := fmt.Sprintf("Time Machine %s: %s", key, val)
		if em.AddEvent(ts, "Collection Time (Backup Configuration)", msg, "os_config",
			"RR-MacOS", "ResponseRay macOS Collector - Time Machine",
			"darwin:os:config_setting", map[string]interface{}{
				"setting": "TimeMachine_" + key,
				"value":   val,
				"group":   "Backup",
				"detail":  v,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Helpers.
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

func pickFirst(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			return v
		}
	}
	return ""
}
