// Package esxi converts the data emitted by the ResponseRay ESXi collector
// (a POSIX shell script) into normalized timeline events. The collector
// writes flat live/*.txt files (output of esxcli, vim-cmd, vmkfstools, vsish)
// plus raw artifacts (vmware logs, hostd logs, audit logs, vmx files).
package esxi

import (
	"bufio"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// Process is the entry point invoked by collectoringest.Run when the manifest
// platform is "esxi". The dirPath argument is the extracted collector output
// root (the directory containing manifest.json, live/, and artifacts/).
func Process(em *core.Emitter, dirPath, ts string) int {
	artifactDir := filepath.Join(dirPath, "artifacts")
	total := 0
	total += processESXiSystemInfo(em, dirPath, ts)
	total += processESXiVMs(em, dirPath, ts)
	total += processESXiProcesses(em, dirPath, ts)
	total += processESXiNetwork(em, dirPath, ts)
	total += processESXiAccounts(em, dirPath, ts)
	total += processESXiPermissions(em, dirPath, ts)
	total += processESXiFirewall(em, dirPath, ts)
	total += processESXiStorage(em, dirPath, ts)
	total += processESXiVIBs(em, dirPath, ts)
	total += processESXiSecurity(em, dirPath, ts)
	total += processESXiLogons(em, dirPath, ts)
	total += processESXiSSH(em, artifactDir, ts)
	total += processESXiPersistence(em, artifactDir, ts)
	total += processESXiVMConfigs(em, artifactDir, ts)
	total += processESXiEnvironment(em, dirPath, ts)
	total += processESXiMultipathing(em, dirPath, ts)
	total += processESXiSCSI(em, dirPath, ts)
	total += processESXiSecPolicy(em, dirPath, ts)
	total += processESXiVmkNic(em, dirPath, ts)
	total += processESXiWBEM(em, dirPath, ts)
	total += processESXiHardware(em, dirPath, ts)
	log.Printf("collectoringest/esxi: parsers added %d events", total)
	return total
}

var reSpace = regexp.MustCompile(`\s+`)

// ---------------------------------------------------------------------------
// esxcli table parser - column boundaries are inferred from the dash line.
// ---------------------------------------------------------------------------

// readEsxcliTable reads an esxcli-style ASCII table file:
//
//	Header1  Header2  Header3
//	-------  -------  -------
//	row1col1 row1col2 row1col3
//	...
//
// Returns a slice of column maps, plus the column names in original order.
func readEsxcliTable(path string) ([]map[string]string, []string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	lines := strings.Split(string(data), "\n")
	var headerIdx = -1
	var dashIdx = -1
	for i := 0; i < len(lines)-1; i++ {
		next := lines[i+1]
		if isDashLine(next) && strings.TrimSpace(lines[i]) != "" {
			headerIdx = i
			dashIdx = i + 1
			break
		}
	}
	if headerIdx < 0 || dashIdx < 0 {
		return nil, nil
	}

	// Compute column ranges from the dash line.
	cols := dashColumnRanges(lines[dashIdx])
	if len(cols) == 0 {
		return nil, nil
	}
	// Read column names by slicing the header.
	headerLine := lines[headerIdx]
	names := make([]string, len(cols))
	for i, c := range cols {
		end := c.end
		if end > len(headerLine) {
			end = len(headerLine)
		}
		start := c.start
		if start > len(headerLine) {
			start = len(headerLine)
		}
		names[i] = strings.TrimSpace(headerLine[start:end])
	}

	var rows []map[string]string
	for i := dashIdx + 1; i < len(lines); i++ {
		line := lines[i]
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		// Stop at another dash line or empty separator.
		if isDashLine(line) {
			break
		}
		row := map[string]string{}
		for j, c := range cols {
			start := c.start
			end := c.end
			if start > len(line) {
				row[names[j]] = ""
				continue
			}
			if j == len(cols)-1 || end > len(line) {
				end = len(line)
			}
			row[names[j]] = strings.TrimSpace(line[start:end])
		}
		rows = append(rows, row)
	}
	return rows, names
}

type colRange struct{ start, end int }

func dashColumnRanges(line string) []colRange {
	var out []colRange
	inDash := false
	start := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '-' {
			if !inDash {
				start = i
				inDash = true
			}
		} else {
			if inDash {
				out = append(out, colRange{start: start, end: i})
				inDash = false
			}
		}
	}
	if inDash {
		out = append(out, colRange{start: start, end: len(line)})
	}
	if len(out) == 0 {
		return nil
	}
	// Stretch each range's end to right before the next range's start, so
	// long values with embedded spaces still land in the correct column.
	for i := 0; i < len(out)-1; i++ {
		// Find midpoint between this column's end and next column's start.
		mid := out[i].end + (out[i+1].start - out[i].end)
		out[i].end = mid
	}
	// Last column has no upper bound.
	out[len(out)-1].end = len(line)
	return out
}

func isDashLine(line string) bool {
	t := strings.TrimSpace(line)
	if t == "" {
		return false
	}
	for _, r := range t {
		if r != '-' && r != ' ' {
			return false
		}
	}
	return strings.Contains(t, "---")
}

// ---------------------------------------------------------------------------
// System info - uname / vmware_version / esxcli_system_version / hostname /
// secureboot / lockdown.
// ---------------------------------------------------------------------------

func processESXiSystemInfo(em *core.Emitter, dirPath, ts string) int {
	added := 0
	pairs := []struct{ file, label, group string }{
		{"uname.txt", "Kernel", "System"},
		{"vmware_version.txt", "VMware Version", "System"},
		{"esxcli_system_version.txt", "ESXi Version", "System"},
		{"esxcli_hostname.txt", "Hostname", "System"},
		{"esxcli_uuid.txt", "Host UUID", "System"},
		{"esxcli_boot_device.txt", "Boot Device", "System"},
		{"esxcli_maintenancemode.txt", "MaintenanceMode", "System"},
		{"esxcli_secureboot.txt", "SecureBoot", "Security"},
		{"esxcli_settings_advanced.txt", "Advanced Settings", "System"},
		{"esxcli_settings_kernel.txt", "Kernel Settings", "System"},
		{"timekeeping.txt", "TimeKeeping", "System"},
		{"uptime.txt", "Uptime", "System"},
		{"lockdown.txt", "Lockdown Mode", "Security"},
	}
	for _, p := range pairs {
		path := filepath.Join(dirPath, "live", p.file)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		body := strings.TrimSpace(string(data))
		if body == "" {
			continue
		}
		val := oneLine(body)
		msg := fmt.Sprintf("System: %s = %s", p.label, val)
		if em.AddEvent(ts, "Collection Time (OS Configuration)", msg, "os_config",
			"RR-ESXi", "ResponseRay ESXi Collector - SystemInfo",
			"esxi:os:config_setting", map[string]interface{}{
				"setting": p.label,
				"value":   val,
				"group":   p.group,
				"detail":  body,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// VMs - parse vim-cmd vmsvc/getallvms (vmlist.txt) for one event per VM.
// ---------------------------------------------------------------------------

// vmlist.txt format (column widths vary):
//
//	Vmid   Name        File                                Guest OS              Version   Annotation
//	1      MyVM        [datastore1] MyVM/MyVM.vmx          windows10_64Guest     vmx-19    Notes
//	16     MyVM2       [datastore1] MyVM2/MyVM2.vmx        ubuntu64Guest         vmx-21    More notes
func processESXiVMs(em *core.Emitter, dirPath, ts string) int {
	p := filepath.Join(dirPath, "live", "vmlist.txt")
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
			if strings.HasPrefix(t, "Vmid") {
				continue
			}
		}
		// Vmid is the first whitespace-separated token; rest gets parsed
		// loosely. We want at minimum: Vmid, Name, vmx-path, Guest OS.
		fields := reSpace.Split(t, 2)
		if len(fields) < 2 || !isAllDigits(fields[0]) {
			continue
		}
		vmid := fields[0]
		rest := fields[1]
		// Rest looks like "Name [datastore] path/file.vmx GuestOS  vmx-NN annotation".
		// We extract the bracketed datastore path as the file, name is what's
		// before that, guest OS is the next token after the .vmx.
		var name, vmxPath, guestOS, version string
		if lb := strings.Index(rest, "["); lb >= 0 {
			name = strings.TrimSpace(rest[:lb])
			tail := rest[lb:]
			// Find the .vmx file end.
			if vmx := strings.Index(tail, ".vmx"); vmx >= 0 {
				vmxPath = strings.TrimSpace(tail[:vmx+4])
				tail = strings.TrimSpace(tail[vmx+4:])
				if tail != "" {
					tf := reSpace.Split(tail, -1)
					if len(tf) >= 1 {
						guestOS = tf[0]
					}
					if len(tf) >= 2 {
						version = tf[1]
					}
				}
			}
		} else {
			name = rest
		}

		msg := fmt.Sprintf("VM: %s (Vmid:%s) %s", name, vmid, guestOS)
		attrs := map[string]interface{}{
			"vm_id":    vmid,
			"vm_name":  name,
			"vmx_path": vmxPath,
			"guest_os": guestOS,
			"version":  version,
			"raw":      t,
		}
		// Decorate with power state / runtime if we have per-VM dumps.
		if power, ok := readESXiOneLine(filepath.Join(dirPath, "live", "vms", vmid, "power.txt")); ok {
			attrs["power_state"] = power
			msg += " [" + power + "]"
		}
		if em.AddEvent(ts, "Collection Time (VM Inventory)", msg, "vm_inventory",
			"RR-ESXi", "ResponseRay ESXi Collector - vmsvc/getallvms",
			"esxi:vm:inventory", attrs) {
			added++
		}
	}
	return added
}

// readESXiOneLine reads the first non-empty line of a small file.
func readESXiOneLine(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t != "" {
			return t, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Processes (worlds) - esxcli system process list.
// ---------------------------------------------------------------------------

// `esxcli system process list` outputs per-process key:value blocks separated
// by blank lines:
//
//	hostd-worker
//	   Name: hostd-worker
//	   World ID: 1234
//	   Process ID: 0
//	   UID: 0
//	   Type: agent
//	   Cartel: 1234
//	   Service: hostd
func processESXiProcesses(em *core.Emitter, dirPath, ts string) int {
	p := filepath.Join(dirPath, "live", "process_list.txt")
	data, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	added := 0
	for _, block := range splitBlankLineBlocks(string(data)) {
		fields := parseKeyValueBlock(block)
		if len(fields) == 0 {
			continue
		}
		name := fields["Name"]
		if name == "" {
			continue
		}
		worldID := fields["World ID"]
		uid := fields["UID"]
		ptype := fields["Type"]
		service := fields["Service"]
		msg := fmt.Sprintf("Running: %s (World:%s) [%s]", name, worldID, ptype)
		attrs := map[string]interface{}{
			"process_name": name,
			"world_id":     worldID,
			"uid":          uid,
			"type":         ptype,
			"service":      service,
			"raw":          block,
		}
		if em.AddEvent(ts, "Collection Time (Process Running)", msg, "running_process",
			"RR-ESXi", "ResponseRay ESXi Collector - esxcli system process list",
			"esxi:process:running", attrs) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Network - esxcli network ip connection list.
// ---------------------------------------------------------------------------

// `esxcli network ip connection list` table:
//
//	Proto  Recv Q  Send Q  Local Address      Foreign Address    State        World ID  CC Algo  World Name
//	-----  ------  ------  -------------      ---------------    -----        --------  -------  ----------
//	tcp    0       0       192.168.1.5:22     192.168.1.10:5432  ESTABLISHED  1234      newreno  sshd
//	tcp    0       0       0.0.0.0:443        0.0.0.0:0          LISTEN       2200      cubic    rhttpproxy
func processESXiNetwork(em *core.Emitter, dirPath, ts string) int {
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "esxcli_connection.txt"))
	if len(rows) == 0 {
		return 0
	}
	added := 0
	for _, row := range rows {
		proto := row["Proto"]
		if proto == "" {
			continue
		}
		state := row["State"]
		local := row["Local Address"]
		foreign := row["Foreign Address"]
		worldID := row["World ID"]
		worldName := row["World Name"]

		localIP, localPort := splitHostPort(local)
		remoteIP, remotePort := splitHostPort(foreign)

		connType := "establishedConnection"
		var msg string
		switch {
		case strings.HasPrefix(proto, "udp"):
			connType = "udpListener"
			msg = fmt.Sprintf("UDP Socket: %s:%s", localIP, localPort)
		case state == "LISTEN":
			connType = "listeningPort"
			msg = fmt.Sprintf("Listening: %s %s:%s", proto, localIP, localPort)
		default:
			msg = fmt.Sprintf("Connected: %s:%s -> %s:%s [%s]", localIP, localPort, remoteIP, remotePort, state)
		}
		if worldName != "" {
			msg += " (" + worldName
			if worldID != "" {
				msg += " World:" + worldID
			}
			msg += ")"
		}

		attrs := map[string]interface{}{
			"connection_type": connType,
			"protocol":        proto,
			"local_ip":        localIP,
			"local_port":      localPort,
			"remote_ip":       remoteIP,
			"remote_port":     remotePort,
			"state":           state,
			"world_id":        worldID,
			"process_name":    worldName,
		}
		if em.AddEvent(ts, "Collection Time (Connection Active)", msg, "active_connection",
			"RR-ESXi", "ResponseRay ESXi Collector - esxcli network ip connection list",
			"esxi:network:connection", attrs) {
			added++
		}
	}
	return added
}

// splitHostPort handles "ip:port" and "[ipv6]:port".
func splitHostPort(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end > 0 {
			return s[1:end], strings.TrimPrefix(s[end+1:], ":")
		}
	}
	if idx := strings.LastIndexByte(s, ':'); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}

// ---------------------------------------------------------------------------
// Accounts - esxcli system account list.
// ---------------------------------------------------------------------------

func processESXiAccounts(em *core.Emitter, dirPath, ts string) int {
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "account_list.txt"))
	added := 0
	for _, row := range rows {
		uid := row["User ID"]
		if uid == "" {
			uid = row["Account ID"]
		}
		desc := row["Description"]
		if uid == "" {
			continue
		}
		msg := "ESXi account: " + uid
		if desc != "" {
			msg += " (" + desc + ")"
		}
		if em.AddEvent(ts, "Account Created/Modified", msg, "account_created",
			"RR-ESXi", "ResponseRay ESXi Collector - esxcli system account",
			"esxi:user:account", map[string]interface{}{
				"username":    uid,
				"description": desc,
				"raw":         row,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Permissions - esxcli system permission list.
// ---------------------------------------------------------------------------

func processESXiPermissions(em *core.Emitter, dirPath, ts string) int {
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "permission_list.txt"))
	added := 0
	for _, row := range rows {
		principal := row["Principal"]
		if principal == "" {
			continue
		}
		role := row["Role"]
		isGroup := row["Is Group"]
		propagate := row["Propagate"]
		msg := fmt.Sprintf("Permission: %s -> %s", principal, role)
		if em.AddEvent(ts, "Collection Time (Permission Configured)", msg, "account_permission",
			"RR-ESXi", "ResponseRay ESXi Collector - esxcli system permission",
			"esxi:user:permission", map[string]interface{}{
				"principal": principal,
				"role":      role,
				"is_group":  isGroup,
				"propagate": propagate,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Firewall - esxcli network firewall ruleset list / rule list.
// ---------------------------------------------------------------------------

func processESXiFirewall(em *core.Emitter, dirPath, ts string) int {
	added := 0
	rulesets, _ := readEsxcliTable(filepath.Join(dirPath, "live", "firewall_ruleset_list.txt"))
	for _, row := range rulesets {
		name := row["Name"]
		if name == "" {
			continue
		}
		enabled := row["Enabled"]
		msg := fmt.Sprintf("Firewall ruleset: %s [Enabled=%s]", name, enabled)
		if em.AddEvent(ts, "Collection Time (Firewall Rule)", msg, "firewall_rule",
			"RR-ESXi", "ResponseRay ESXi Collector - firewall ruleset",
			"esxi:firewall:ruleset", map[string]interface{}{
				"setting":      "ruleset",
				"ruleset_name": name,
				"enabled":      enabled,
				"raw":          row,
			}) {
			added++
		}
	}
	rules, _ := readEsxcliTable(filepath.Join(dirPath, "live", "firewall_ruleset_rule_list.txt"))
	for _, row := range rules {
		name := row["Ruleset"]
		if name == "" {
			name = row["Name"]
		}
		direction := row["Direction"]
		proto := row["Protocol"]
		portType := row["Port Type"]
		portBegin := row["Port"]
		portEnd := row["End Port"]
		if name == "" {
			continue
		}
		msg := fmt.Sprintf("Firewall rule: %s %s %s %s/%s-%s", name, direction, proto, portType, portBegin, portEnd)
		if em.AddEvent(ts, "Collection Time (Firewall Rule)", msg, "firewall_rule",
			"RR-ESXi", "ResponseRay ESXi Collector - firewall rule",
			"esxi:firewall:rule", map[string]interface{}{
				"setting":      "rule",
				"ruleset_name": name,
				"direction":    direction,
				"protocol":     proto,
				"port_type":    portType,
				"port_begin":   portBegin,
				"port_end":     portEnd,
				"raw":          row,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Storage - esxcli storage filesystem list.
// ---------------------------------------------------------------------------

func processESXiStorage(em *core.Emitter, dirPath, ts string) int {
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "storage_filesystem.txt"))
	added := 0
	for _, row := range rows {
		mount := row["Mount Point"]
		if mount == "" {
			continue
		}
		volName := row["Volume Name"]
		fsType := row["Type"]
		uuid := row["UUID"]
		size := row["Size"]
		free := row["Free"]
		msg := fmt.Sprintf("Datastore: %s (%s) at %s", volName, fsType, mount)
		if em.AddEvent(ts, "Collection Time (Datastore Mounted)", msg, "datastore",
			"RR-ESXi", "ResponseRay ESXi Collector - storage filesystem",
			"esxi:storage:filesystem", map[string]interface{}{
				"volume_name": volName,
				"mount_point": mount,
				"fs_type":     fsType,
				"uuid":        uuid,
				"size":        size,
				"free":        free,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// VIBs - esxcli software vib list.
// ---------------------------------------------------------------------------

// `esxcli software vib list` table columns:
//
//	Name           Version           Vendor   Acceptance Level    Install Date
//	------------   ---------------   ------   ------------------  ------------
//	cpu-microcode  7.0.3-0.0.20842819 VMware  VMwareCertified     2024-01-15
func processESXiVIBs(em *core.Emitter, dirPath, ts string) int {
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "software_vib_list.txt"))
	added := 0
	for _, row := range rows {
		name := row["Name"]
		if name == "" {
			continue
		}
		version := row["Version"]
		vendor := row["Vendor"]
		acceptance := row["Acceptance Level"]
		install := row["Install Date"]

		t := ts
		desc := "Collection Time (Program Installed)"
		if install != "" {
			t = install + "T00:00:00"
			desc = "Program Install Date"
		}
		msg := fmt.Sprintf("VIB: %s v%s [%s, %s]", name, version, vendor, acceptance)
		if em.AddEvent(t, desc, msg, "installed_program",
			"RR-ESXi", "ResponseRay ESXi Collector - software vib list",
			"esxi:vib:installed", map[string]interface{}{
				"program_name":     name,
				"version":          version,
				"vendor":           vendor,
				"acceptance_level": acceptance,
				"install_date":     install,
				"source":           "esxcli vib",
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Security - secureboot, tpm, keystore, lockdown.
// ---------------------------------------------------------------------------

func processESXiSecurity(em *core.Emitter, dirPath, ts string) int {
	added := 0
	pairs := []struct{ file, label string }{
		{"secureboot.txt", "SecureBoot"},
		{"tpm.txt", "TPM"},
		{"keystore.txt", "KeyPersistence"},
		{"lockdown.txt", "Lockdown"},
	}
	for _, p := range pairs {
		path := filepath.Join(dirPath, "live", p.file)
		body, err := os.ReadFile(path)
		if err != nil || len(strings.TrimSpace(string(body))) == 0 {
			continue
		}
		val := oneLine(string(body))
		msg := fmt.Sprintf("Security: %s = %s", p.label, val)
		if em.AddEvent(ts, "Collection Time (OS Configuration)", msg, "os_config",
			"RR-ESXi", "ResponseRay ESXi Collector - Security",
			"esxi:os:config_setting", map[string]interface{}{
				"setting": p.label,
				"value":   val,
				"group":   "Security",
				"detail":  string(body),
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Logons - last.txt and who.txt produced by busybox last/who.
// ---------------------------------------------------------------------------

// busybox `last` output columns vary slightly from glibc:
//
//	root  pts/0  192.168.1.10  Thu Apr 20 18:00 - 19:00 (00:59)
//	user  pts/1  192.168.1.20  Thu Apr 20 19:00   still logged in
func processESXiLogons(em *core.Emitter, dirPath, ts string) int {
	added := 0
	for _, name := range []string{"last", "who"} {
		path := filepath.Join(dirPath, "live", name+".txt")
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			t := strings.TrimSpace(line)
			if t == "" || strings.HasPrefix(t, "wtmp") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			user := fields[0]
			term := fields[1]
			from := ""
			if len(fields) >= 3 {
				from = fields[2]
			}
			msg := fmt.Sprintf("Logon: user=%s tty=%s from=%s", user, term, from)
			if em.AddEvent(ts, "Logon Recorded", msg, "logon_success",
				"RR-ESXi", "ResponseRay ESXi Collector - "+name,
				"esxi:auth:wtmp", map[string]interface{}{
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

// ---------------------------------------------------------------------------
// SSH - sshd_config snapshot under artifacts/persistence (ESXi collector
// stores ssh under persistence rather than its own dir).
// ---------------------------------------------------------------------------

func processESXiSSH(em *core.Emitter, artifactDir, ts string) int {
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
		mtime := core.FileMtimeISO(info.ModTime())
		rel, _ := filepath.Rel(root, path)
		switch {
		case base == "authorized_keys" || base == "authorized_keys2":
			f, ferr := os.Open(path)
			if ferr != nil {
				return nil
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 1024*1024), 4*1024*1024)
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
				if em.AddEvent(mtime, "SSH Authorized Key Added",
					fmt.Sprintf("SSH authorized_key: %s %s", keyType, keyComment),
					"ssh_authorized_key",
					"RR-ESXi", "ResponseRay ESXi Collector - SSH",
					"esxi:ssh:authorized_key", map[string]interface{}{
						"key_type":      keyType,
						"key_comment":   keyComment,
						"key_data":      fields[1],
						"artifact_path": filepath.ToSlash(filepath.Join("ssh", rel)),
					}) {
					added++
				}
			}
		default:
			if em.AddEvent(mtime, "SSH Config Modified",
				fmt.Sprintf("SSH config file: %s", base),
				"os_config",
				"RR-ESXi", "ResponseRay ESXi Collector - SSH",
				"esxi:os:config_setting", map[string]interface{}{
					"setting":       "ssh_config",
					"file_name":     d.Name(),
					"file_size":     info.Size(),
					"artifact_path": filepath.ToSlash(filepath.Join("ssh", rel)),
				}) {
				added++
			}
		}
		_ = ts
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// Persistence - one startup_item per file under artifacts/persistence.
// ---------------------------------------------------------------------------

func processESXiPersistence(em *core.Emitter, artifactDir, ts string) int {
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
		mtime := core.FileMtimeISO(info.ModTime())

		category := "persistence"
		switch {
		case strings.Contains(rel, "init.d"):
			category = "init_script"
		case strings.HasSuffix(rel, "rc.local") || strings.HasSuffix(rel, "local.sh"):
			category = "rc_local"
		case strings.Contains(rel, "cron"):
			category = "cron"
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
			"RR-ESXi", "ResponseRay ESXi Collector - Persistence",
			"esxi:persistence:file", attrs) {
			added++
		}
		if em.AddEvent(ts, "Collection Time (Persistence Configured)", msg, "startup_item",
			"RR-ESXi", "ResponseRay ESXi Collector - Persistence",
			"esxi:persistence:file", core.CopyAttrs(attrs)) {
			added++
		}
		return nil
	})
	return added
}

// ---------------------------------------------------------------------------
// VM configs - one vm_inventory event per .vmx file captured under artifacts/vms.
// ---------------------------------------------------------------------------

func processESXiVMConfigs(em *core.Emitter, artifactDir, ts string) int {
	root := filepath.Join(artifactDir, "vms")
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
		case ".vmx", ".vmsd", ".nvram", ".log":
		default:
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		mtime := core.FileMtimeISO(info.ModTime())

		etype := "vm_inventory"
		desc := "VM Config Captured"
		if ext == ".log" {
			etype = "vm_log"
			desc = "VM Log Captured"
		}
		msg := fmt.Sprintf("VM file: %s", rel)
		attrs := map[string]interface{}{
			"file_path":     rel,
			"file_name":     d.Name(),
			"file_size":     info.Size(),
			"file_ext":      ext,
			"artifact_path": filepath.ToSlash(filepath.Join("vms", rel)),
		}
		// Best-effort: parse displayName and guestOS from .vmx for context.
		if ext == ".vmx" && info.Size() < 256*1024 {
			if vmxAttrs := parseVMXSummary(path); vmxAttrs != nil {
				for k, v := range vmxAttrs {
					attrs[k] = v
				}
				if name, ok := vmxAttrs["display_name"].(string); ok && name != "" {
					msg = "VM config: " + name
				}
			}
		}
		if em.AddEvent(mtime, desc, msg, etype,
			"RR-ESXi", "ResponseRay ESXi Collector - VM files",
			"esxi:vm:file", attrs) {
			added++
		}
		_ = ts
		return nil
	})
	return added
}

// parseVMXSummary extracts a few useful keys from a .vmx file. .vmx files are
// `key = "value"` lines, one per line.
func parseVMXSummary(path string) map[string]interface{} {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	out := map[string]interface{}{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(strings.Trim(line[eq+1:], `"`))
		switch k {
		case "displayName":
			out["display_name"] = v
		case "guestOS":
			out["guest_os"] = v
		case "uuid.bios":
			out["uuid_bios"] = v
		case "vc.uuid":
			out["vc_uuid"] = v
		case "annotation":
			out["annotation"] = v
		case "ethernet0.address":
			out["mac_address"] = v
		case "memSize":
			out["mem_size"] = v
		case "numvcpus":
			out["num_vcpus"] = v
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Environment variables - env or printenv output (KEY=VALUE lines).
// ---------------------------------------------------------------------------

func processESXiEnvironment(em *core.Emitter, dirPath, ts string) int {
	added := 0
	for _, name := range []string{"environment.txt", "printenv.txt"} {
		path := filepath.Join(dirPath, "live", name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if t == "" || !strings.Contains(t, "=") {
				continue
			}
			idx := strings.Index(t, "=")
			key := t[:idx]
			val := t[idx+1:]
			if key == "" {
				continue
			}
			msg := fmt.Sprintf("Environment: %s = %s", key, truncate(val, 100))
			if em.AddEvent(ts, "Collection Time (Environment Variable)", msg, "esxi_environment",
				"RR-ESXi", "ResponseRay ESXi Collector - Environment",
				"esxi:system:environment", map[string]interface{}{
					"variable_name":  key,
					"variable_value": val,
				}) {
				added++
			}
		}
		break // Only need one source
	}
	return added
}

// ---------------------------------------------------------------------------
// Multipathing - esxcli storage nmp device/path list.
// ---------------------------------------------------------------------------

func processESXiMultipathing(em *core.Emitter, dirPath, ts string) int {
	added := 0
	// Parse storage_nmp_device.txt
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "storage_nmp_device.txt"))
	for _, row := range rows {
		device := row["Device"]
		if device == "" {
			device = row["Device Display Name"]
		}
		if device == "" {
			continue
		}
		pathPolicy := row["Path Selection Policy"]
		storageArray := row["Storage Array Type"]
		msg := fmt.Sprintf("Multipath Device: %s [%s, %s]", device, pathPolicy, storageArray)
		if em.AddEvent(ts, "Collection Time (Multipath Device)", msg, "esxi_multipath",
			"RR-ESXi", "ResponseRay ESXi Collector - Multipathing",
			"esxi:storage:multipath", map[string]interface{}{
				"device":             device,
				"path_policy":        pathPolicy,
				"storage_array_type": storageArray,
				"raw":                row,
			}) {
			added++
		}
	}
	// Parse storage_nmp_path.txt
	rows, _ = readEsxcliTable(filepath.Join(dirPath, "live", "storage_nmp_path.txt"))
	for _, row := range rows {
		runtime := row["Runtime Name"]
		if runtime == "" {
			continue
		}
		device := row["Device"]
		state := row["State"]
		adapter := row["Adapter"]
		msg := fmt.Sprintf("Multipath Path: %s -> %s [%s]", runtime, device, state)
		if em.AddEvent(ts, "Collection Time (Multipath Path)", msg, "esxi_multipath_path",
			"RR-ESXi", "ResponseRay ESXi Collector - Multipathing",
			"esxi:storage:multipath_path", map[string]interface{}{
				"runtime_name": runtime,
				"device":       device,
				"state":        state,
				"adapter":      adapter,
				"raw":          row,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// SCSI - esxcli storage san/scsi device list.
// ---------------------------------------------------------------------------

func processESXiSCSI(em *core.Emitter, dirPath, ts string) int {
	added := 0
	// FC adapters
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "storage_san_adapter.txt"))
	for _, row := range rows {
		adapter := row["Adapter"]
		if adapter == "" {
			continue
		}
		wwnn := row["Node Name"]
		wwpn := row["Port Name"]
		msg := fmt.Sprintf("FC Adapter: %s WWPN=%s", adapter, wwpn)
		if em.AddEvent(ts, "Collection Time (SCSI FC Adapter)", msg, "esxi_scsi",
			"RR-ESXi", "ResponseRay ESXi Collector - SCSI",
			"esxi:storage:scsi_adapter", map[string]interface{}{
				"adapter": adapter,
				"wwnn":    wwnn,
				"wwpn":    wwpn,
				"raw":     row,
			}) {
			added++
		}
	}
	// iSCSI adapters
	rows, _ = readEsxcliTable(filepath.Join(dirPath, "live", "storage_san_iscsi.txt"))
	for _, row := range rows {
		adapter := row["Adapter"]
		if adapter == "" {
			continue
		}
		name := row["Name"]
		driver := row["Driver"]
		msg := fmt.Sprintf("iSCSI Adapter: %s (%s)", adapter, name)
		if em.AddEvent(ts, "Collection Time (SCSI iSCSI Adapter)", msg, "esxi_iscsi",
			"RR-ESXi", "ResponseRay ESXi Collector - SCSI",
			"esxi:storage:iscsi_adapter", map[string]interface{}{
				"adapter": adapter,
				"name":    name,
				"driver":  driver,
				"raw":     row,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Security Policy Domain - esxcli system secpolicy domain list.
// ---------------------------------------------------------------------------

func processESXiSecPolicy(em *core.Emitter, dirPath, ts string) int {
	added := 0
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "secpolicy_domain.txt"))
	for _, row := range rows {
		domain := row["Domain"]
		if domain == "" {
			domain = row["Name"]
		}
		if domain == "" {
			continue
		}
		level := row["Enforcement Level"]
		enabled := row["Enabled"]
		msg := fmt.Sprintf("Security Policy: %s [Enforcement=%s, Enabled=%s]", domain, level, enabled)
		if em.AddEvent(ts, "Collection Time (Security Policy)", msg, "esxi_secpolicy",
			"RR-ESXi", "ResponseRay ESXi Collector - SecurityPolicy",
			"esxi:security:policy", map[string]interface{}{
				"domain":            domain,
				"enforcement_level": level,
				"enabled":           enabled,
				"raw":               row,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// VmkNic - esxcli network ip interface ipv4/ipv6 address list.
// ---------------------------------------------------------------------------

func processESXiVmkNic(em *core.Emitter, dirPath, ts string) int {
	added := 0
	// IPv4 addresses
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "vmknic_list.txt"))
	for _, row := range rows {
		name := row["Name"]
		if name == "" {
			name = row["Interface"]
		}
		if name == "" {
			continue
		}
		ipv4 := row["IPv4 Address"]
		if ipv4 == "" {
			ipv4 = row["Address"]
		}
		netmask := row["IPv4 Netmask"]
		if netmask == "" {
			netmask = row["Netmask"]
		}
		gateway := row["IPv4 Gateway"]
		addrType := row["Address Type"]
		msg := fmt.Sprintf("VMkernel NIC: %s %s/%s [%s]", name, ipv4, netmask, addrType)
		if em.AddEvent(ts, "Collection Time (VMkernel NIC)", msg, "esxi_vmknic",
			"RR-ESXi", "ResponseRay ESXi Collector - VmkNic",
			"esxi:network:vmknic", map[string]interface{}{
				"interface":    name,
				"ipv4_address": ipv4,
				"netmask":      netmask,
				"gateway":      gateway,
				"address_type": addrType,
				"raw":          row,
			}) {
			added++
		}
	}
	// IPv6 addresses
	rows, _ = readEsxcliTable(filepath.Join(dirPath, "live", "vmknic_ipv6.txt"))
	for _, row := range rows {
		name := row["Name"]
		if name == "" {
			name = row["Interface"]
		}
		if name == "" {
			continue
		}
		ipv6 := row["IPv6 Address"]
		if ipv6 == "" {
			ipv6 = row["Address"]
		}
		prefix := row["Prefix Length"]
		addrType := row["Type"]
		msg := fmt.Sprintf("VMkernel NIC (IPv6): %s %s/%s", name, ipv6, prefix)
		if em.AddEvent(ts, "Collection Time (VMkernel NIC IPv6)", msg, "esxi_vmknic",
			"RR-ESXi", "ResponseRay ESXi Collector - VmkNic",
			"esxi:network:vmknic_ipv6", map[string]interface{}{
				"interface":     name,
				"ipv6_address":  ipv6,
				"prefix_length": prefix,
				"address_type":  addrType,
				"raw":           row,
			}) {
			added++
		}
	}
	// Portgroups
	rows, _ = readEsxcliTable(filepath.Join(dirPath, "live", "vmknic_portgroup.txt"))
	for _, row := range rows {
		name := row["Name"]
		if name == "" {
			continue
		}
		vswitch := row["Virtual Switch"]
		vlanID := row["VLAN ID"]
		msg := fmt.Sprintf("Portgroup: %s on %s (VLAN %s)", name, vswitch, vlanID)
		if em.AddEvent(ts, "Collection Time (vSwitch Portgroup)", msg, "esxi_portgroup",
			"RR-ESXi", "ResponseRay ESXi Collector - VmkNic",
			"esxi:network:portgroup", map[string]interface{}{
				"name":           name,
				"virtual_switch": vswitch,
				"vlan_id":        vlanID,
				"raw":            row,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// WBEM - esxcli system wbem get/provider list.
// ---------------------------------------------------------------------------

func processESXiWBEM(em *core.Emitter, dirPath, ts string) int {
	added := 0
	// WBEM config (get)
	path := filepath.Join(dirPath, "live", "wbem_get.txt")
	data, err := os.ReadFile(path)
	if err == nil && len(data) > 0 {
		fields := parseKeyValueBlock(string(data))
		if len(fields) > 0 {
			enabled := fields["Enabled"]
			port := fields["Port"]
			loglevel := fields["Loglevel"]
			msg := fmt.Sprintf("WBEM Config: Enabled=%s Port=%s Loglevel=%s", enabled, port, loglevel)
			if em.AddEvent(ts, "Collection Time (WBEM Configuration)", msg, "esxi_wbem",
				"RR-ESXi", "ResponseRay ESXi Collector - WBEM",
				"esxi:system:wbem_config", map[string]interface{}{
					"enabled":  enabled,
					"port":     port,
					"loglevel": loglevel,
					"raw":      fields,
				}) {
				added++
			}
		}
	}
	// WBEM providers
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "wbem_provider_list.txt"))
	for _, row := range rows {
		name := row["Name"]
		if name == "" {
			continue
		}
		status := row["Status"]
		msg := fmt.Sprintf("WBEM Provider: %s [%s]", name, status)
		if em.AddEvent(ts, "Collection Time (WBEM Provider)", msg, "esxi_wbem_provider",
			"RR-ESXi", "ResponseRay ESXi Collector - WBEM",
			"esxi:system:wbem_provider", map[string]interface{}{
				"provider_name": name,
				"status":        status,
				"raw":           row,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Hardware - additional hardware info (CPU, PCI, clock).
// ---------------------------------------------------------------------------

func processESXiHardware(em *core.Emitter, dirPath, ts string) int {
	added := 0
	// CPU info
	rows, _ := readEsxcliTable(filepath.Join(dirPath, "live", "hardware_cpu.txt"))
	for _, row := range rows {
		id := row["CPU"]
		if id == "" {
			id = row["Id"]
		}
		if id == "" {
			continue
		}
		family := row["Family"]
		model := row["Model"]
		brand := row["Brand"]
		msg := fmt.Sprintf("CPU: %s - %s (Family %s, Model %s)", id, brand, family, model)
		if em.AddEvent(ts, "Collection Time (CPU Info)", msg, "esxi_cpu",
			"RR-ESXi", "ResponseRay ESXi Collector - Hardware",
			"esxi:hardware:cpu", map[string]interface{}{
				"cpu_id": id,
				"family": family,
				"model":  model,
				"brand":  brand,
				"raw":    row,
			}) {
			added++
		}
	}
	// PCI devices
	rows, _ = readEsxcliTable(filepath.Join(dirPath, "live", "hardware_pci.txt"))
	for _, row := range rows {
		addr := row["Address"]
		if addr == "" {
			continue
		}
		vendorName := row["Vendor Name"]
		deviceName := row["Device Name"]
		className := row["Device Class Name"]
		msg := fmt.Sprintf("PCI: %s - %s %s (%s)", addr, vendorName, deviceName, className)
		if em.AddEvent(ts, "Collection Time (PCI Device)", msg, "esxi_pci",
			"RR-ESXi", "ResponseRay ESXi Collector - Hardware",
			"esxi:hardware:pci", map[string]interface{}{
				"address":     addr,
				"vendor_name": vendorName,
				"device_name": deviceName,
				"class_name":  className,
				"raw":         row,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

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

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// splitBlankLineBlocks splits text into blocks separated by one or more blank lines.
func splitBlankLineBlocks(text string) []string {
	var out []string
	var cur []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			if len(cur) > 0 {
				out = append(out, strings.Join(cur, "\n"))
				cur = cur[:0]
			}
			continue
		}
		cur = append(cur, line)
	}
	if len(cur) > 0 {
		out = append(out, strings.Join(cur, "\n"))
	}
	return out
}

// parseKeyValueBlock parses "Key: Value" lines into a map.
func parseKeyValueBlock(block string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(block, "\n") {
		t := strings.TrimSpace(line)
		idx := strings.IndexByte(t, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(t[:idx])
		val := strings.TrimSpace(t[idx+1:])
		if key != "" {
			out[key] = val
		}
	}
	return out
}
