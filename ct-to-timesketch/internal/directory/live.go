package directory

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

// ProcessLiveData reads all live/*.json files from the collector output directory
// and converts them to timeline events.
func ProcessLiveData(dirPath string, conv *converter.Converter, collectionTime string) int {
	liveDir := filepath.Join(dirPath, "live")
	if _, err := os.Stat(liveDir); os.IsNotExist(err) {
		progress.Warning("No live/ directory found in collector output")
		return 0
	}

	total := 0

	type liveHandler struct {
		filename string
		handler  func(string, *converter.Converter, string) int
	}

	handlers := []liveHandler{
		{"processes.json", processProcesses},
		{"connections.json", processConnections},
		{"dns_cache.json", processDNSCache},
		{"arp_cache.json", processARPCache},
		{"routing_table.json", processRoutingTable},
		{"logon_sessions.json", processLogonSessions},
		{"user_accounts.json", processUserAccounts},
		{"services.json", processServices},
		{"startup_items.json", processStartupItems},
		{"devices.json", processDevices},
		{"user_accessed_data.json", processUserAccessedData},
		{"os_config.json", processOSConfig},
	}

	for _, h := range handlers {
		path := filepath.Join(liveDir, h.filename)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		n := h.handler(path, conv, collectionTime)
		if n > 0 {
			progress.Info(fmt.Sprintf("  %s: %d events", h.filename, n))
		}
		total += n
	}

	return total
}

// ProcessFilesystemJSONL reads live/filesystem.jsonl and creates MACB file timeline events.
// Returns the number of events added.
func ProcessFilesystemJSONL(dirPath string, conv *converter.Converter) int {
	fsPath := filepath.Join(dirPath, "live", "filesystem.jsonl")
	if _, err := os.Stat(fsPath); os.IsNotExist(err) {
		return 0
	}

	f, err := os.Open(fsPath)
	if err != nil {
		progress.Warning(fmt.Sprintf("Cannot open filesystem.jsonl: %v", err))
		return 0
	}
	defer f.Close()

	total := 0
	lineCount := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		lineCount++
		if lineCount%100000 == 0 {
			progress.ProgressLine("Filesystem: %d entries processed (%d events)", lineCount, total)
		}

		var entry struct {
			Path      string `json:"path"`
			Name      string `json:"name"`
			Size      int64  `json:"size"`
			IsDir     bool   `json:"is_directory"`
			Created   string `json:"created"`
			Modified  string `json:"modified"`
			Accessed  string `json:"accessed"`
			Extension string `json:"extension"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		prefix := "File"
		metaType := "File"
		if entry.IsDir {
			prefix = "Directory"
			metaType = "Dir"
		}

		baseAttrs := map[string]interface{}{
			"file_path": entry.Path,
			"file_name": entry.Name,
			"file_size": entry.Size,
			"meta_type": metaType,
		}
		if entry.Extension != "" {
			baseAttrs["file_extension"] = entry.Extension
		}

		macbFields := []struct {
			ts   string
			desc string
		}{
			{entry.Modified, "File Modified"},
			{entry.Accessed, "File Accessed"},
			{entry.Created, "File Created"},
		}

		for _, f := range macbFields {
			if f.ts == "" {
				continue
			}
			cp := copyAttrs(baseAttrs)
			if conv.AddEvent(f.ts, f.desc, prefix+": "+entry.Path, "file_timeline",
				"RR-FileSystem", "ResponseRay Collector - Filesystem Enumeration",
				"fs:stat", cp) {
				total++
			}
		}
	}

	if lineCount > 0 {
		progress.ProgressDone()
	}
	return total
}

// ----------- Individual live data file processors -----------

func processProcesses(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		PID       int      `json:"pid"`
		PPID      int      `json:"ppid"`
		Name      string   `json:"name"`
		Path      string   `json:"path"`
		CmdLine   string   `json:"command_line"`
		User      string   `json:"user"`
		StartTime *string  `json:"start_time"`
		MD5       string   `json:"md5"`
		Modules   []string `json:"modules"`
		MemoryMB  float64  `json:"memory_mb"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("processes.json: %v", err))
		return 0
	}

	added := 0
	for _, p := range entries {
		ts := collectionTime
		tsDesc := "Collection Time (Process Running)"
		if p.StartTime != nil && *p.StartTime != "" {
			ts = *p.StartTime
			tsDesc = "Process Start Time"
		}

		name := p.Name
		if name == "" {
			name = "unknown"
		}

		msg := fmt.Sprintf("Running: %s (PID:%d)", name, p.PID)
		if p.CmdLine != "" {
			display := p.CmdLine
			if len(display) > 100 {
				display = display[:100] + "..."
			}
			msg += " " + display
		}

		userID, userDomain := splitUser(p.User)

		attrs := map[string]interface{}{
			"process_name": name,
			"process_path": p.Path,
			"command_line": p.CmdLine,
			"pid":          fmt.Sprint(p.PID),
			"ppid":         fmt.Sprint(p.PPID),
			"user_id":      userID,
			"user_domain":  userDomain,
			"md5":          p.MD5,
			"memory_mb":    p.MemoryMB,
		}
		if len(p.Modules) > 0 && len(p.Modules) <= 50 {
			attrs["loaded_modules"] = strings.Join(p.Modules, "; ")
		} else if len(p.Modules) > 50 {
			attrs["loaded_modules"] = fmt.Sprintf("%d modules loaded", len(p.Modules))
		}

		if conv.AddEvent(ts, tsDesc, msg, "running_process",
			"RR-Collector", "ResponseRay Collector - Running Processes",
			"ct:memory:process", attrs) {
			added++
		}
	}
	return added
}

func processConnections(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		Protocol    string `json:"protocol"`
		LocalAddr   string `json:"local_address"`
		LocalPort   int    `json:"local_port"`
		RemoteAddr  string `json:"remote_address"`
		RemotePort  int    `json:"remote_port"`
		State       string `json:"state"`
		PID         int    `json:"pid"`
		ProcessName string `json:"process_name"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("connections.json: %v", err))
		return 0
	}

	added := 0
	for _, c := range entries {
		var msg string
		connType := "establishedConnection"
		localPort := fmt.Sprint(c.LocalPort)
		remotePort := fmt.Sprint(c.RemotePort)

		switch {
		case c.State == "LISTEN" || c.State == "Listening":
			connType = "listeningPort"
			msg = fmt.Sprintf("Listening: %s %s:%s", c.Protocol, c.LocalAddr, localPort)
		case c.Protocol == "UDP":
			connType = "udpListener"
			msg = fmt.Sprintf("UDP Listener: %s:%s", c.LocalAddr, localPort)
		default:
			msg = fmt.Sprintf("Connected: %s:%s -> %s:%s", c.LocalAddr, localPort, c.RemoteAddr, remotePort)
		}
		if c.PID > 0 {
			msg += fmt.Sprintf(" (PID:%d %s)", c.PID, c.ProcessName)
		}

		attrs := map[string]interface{}{
			"connection_type": connType,
			"protocol":        c.Protocol,
			"local_ip":        c.LocalAddr,
			"local_port":      localPort,
			"remote_ip":       c.RemoteAddr,
			"remote_port":     remotePort,
			"pid":             fmt.Sprint(c.PID),
			"state":           c.State,
			"process_name":    c.ProcessName,
		}

		if conv.AddEvent(collectionTime, "Collection Time (Connection Active)", msg, "active_connection",
			"RR-Collector", "ResponseRay Collector - Network Connections",
			"windows:network:connection", attrs) {
			added++
		}
	}
	return added
}

func processDNSCache(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
		Data string `json:"data"`
		TTL  int    `json:"ttl"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("dns_cache.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		if e.Name == "" {
			continue
		}
		msg := "DNS Cache: " + e.Name
		if e.Data != "" {
			msg += " -> " + e.Data
		} else {
			msg += " (no data cached)"
		}

		if conv.AddEvent(collectionTime, "Collection Time (DNS Cache Snapshot)", msg,
			"dns_cache_entry", "RR-Collector", "ResponseRay Collector - DNS Cache",
			"ct:memory:dns_cache", map[string]interface{}{
				"hostname":    e.Name,
				"resolved_ip": e.Data,
				"record_type": e.Type,
				"ttl":         e.TTL,
			}) {
			added++
		}
	}
	return added
}

func processARPCache(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		IPAddress      string `json:"ip_address"`
		MACAddress     string `json:"mac_address"`
		Type           string `json:"type"`
		InterfaceIndex int    `json:"interface_index"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("arp_cache.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		if e.IPAddress == "" {
			continue
		}
		if conv.AddEvent(collectionTime, "Collection Time (ARP Cache Snapshot)",
			fmt.Sprintf("ARP Cache: %s -> %s", e.IPAddress, e.MACAddress),
			"arp_cache_entry", "RR-Collector", "ResponseRay Collector - ARP Cache",
			"ct:memory:arp_cache", map[string]interface{}{
				"ip_address":  e.IPAddress,
				"mac_address": e.MACAddress,
				"arp_type":    e.Type,
			}) {
			added++
		}
	}
	return added
}

func processRoutingTable(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		Destination      string `json:"destination"`
		Netmask          string `json:"netmask"`
		Gateway          string `json:"gateway"`
		InterfaceAddress string `json:"interface_address"`
		Metric           int    `json:"metric"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("routing_table.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		if e.Destination == "" {
			continue
		}
		msg := "Route: " + e.Destination
		if e.Gateway != "" && e.Gateway != "0.0.0.0" {
			msg += " via " + e.Gateway
		} else {
			msg += " (direct)"
		}

		if conv.AddEvent(collectionTime, "Collection Time (Routing Table Snapshot)", msg,
			"routing_entry", "RR-Collector", "ResponseRay Collector - Routing Table",
			"ct:memory:routing_table", map[string]interface{}{
				"destination":       e.Destination,
				"netmask":           e.Netmask,
				"next_hop":          e.Gateway,
				"interface_address": e.InterfaceAddress,
				"metric":            e.Metric,
			}) {
			added++
		}
	}
	return added
}

func processLogonSessions(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		LogonID     string  `json:"logon_id"`
		Username    string  `json:"username"`
		Domain      string  `json:"domain"`
		SID         string  `json:"sid"`
		LogonType   string  `json:"logon_type"`
		LogonTime   *string `json:"logon_time"`
		AuthPackage string  `json:"auth_package"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("logon_sessions.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		ts := collectionTime
		tsDesc := "Collection Time (Logon Session Active)"
		if e.LogonTime != nil && *e.LogonTime != "" {
			ts = *e.LogonTime
			tsDesc = "Logon Session Start"
		}

		u := e.Username
		if e.Domain != "" {
			u = e.Domain + "\\" + e.Username
		}
		msg := "Logon session: " + u
		if e.LogonType != "" {
			msg += " (Type: " + e.LogonType + ")"
		}

		if conv.AddEvent(ts, tsDesc, msg, "logon_session",
			"RR-Collector", "ResponseRay Collector - Logon Sessions",
			"windows:logon:session", map[string]interface{}{
				"user_id":      e.Username,
				"user_domain":  e.Domain,
				"user_sid":     e.SID,
				"logon_type":   e.LogonType,
				"logon_id":     e.LogonID,
				"auth_package": e.AuthPackage,
			}) {
			added++
		}
	}
	return added
}

func processUserAccounts(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		Username        string   `json:"username"`
		FullName        string   `json:"full_name"`
		SID             string   `json:"sid"`
		IsDisabled      bool     `json:"is_disabled"`
		IsLocked        bool     `json:"is_locked"`
		LastLogon       *string  `json:"last_logon"`
		PasswordLastSet *string  `json:"password_last_set"`
		Groups          []string `json:"groups"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("user_accounts.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		ts := collectionTime
		if e.LastLogon != nil && *e.LastLogon != "" {
			ts = *e.LastLogon
		}

		msg := "User account: " + e.Username
		if e.FullName != "" {
			msg += " (" + e.FullName + ")"
		}
		if e.IsDisabled {
			msg += " [DISABLED]"
		}
		if e.IsLocked {
			msg += " [LOCKED]"
		}

		status := "active"
		if e.IsDisabled {
			status = "disabled"
		}
		if e.IsLocked {
			status = "locked"
		}

		var isAdmin interface{}
		for _, g := range e.Groups {
			if strings.EqualFold(g, "Administrators") {
				isAdmin = true
				msg += " [ADMIN]"
				break
			}
		}

		if conv.AddEvent(ts, "Account Created/Modified", msg, "account_created",
			"RR-Collector", "ResponseRay Collector - User Accounts",
			"windows:registry:sam_users", map[string]interface{}{
				"username":          e.Username,
				"full_name":         e.FullName,
				"user_sid":          e.SID,
				"account_status":    status,
				"admin_priv":        isAdmin,
				"groups":            strings.Join(e.Groups, ", "),
				"password_last_set": e.PasswordLastSet,
			}) {
			added++
		}
	}
	return added
}

func processServices(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		Name        string `json:"name"`
		DisplayName string `json:"display_name"`
		BinaryPath  string `json:"binary_path"`
		StartType   string `json:"start_type"`
		Status      string `json:"status"`
		Account     string `json:"account"`
		Description string `json:"description"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("services.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		msg := "Service: " + e.Name
		if e.DisplayName != "" && e.DisplayName != e.Name {
			msg += " (" + e.DisplayName + ")"
		}
		msg += " [" + e.Status + "]"

		if conv.AddEvent(collectionTime, "Collection Time (Service Configuration)", msg, "startup_item",
			"RR-Collector", "ResponseRay Collector - Windows Services",
			"windows:registry:run", map[string]interface{}{
				"config_type":  "Service",
				"description":  e.Description,
				"details":      e.BinaryPath,
				"arguments":    "",
				"start_type":   e.StartType,
				"status":       e.Status,
				"account":      e.Account,
				"service_name": e.Name,
				"display_name": e.DisplayName,
			}) {
			added++
		}
	}
	return added
}

func processStartupItems(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		Name     string `json:"name"`
		Command  string `json:"command"`
		Location string `json:"location"`
		User     string `json:"user"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("startup_items.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		msg := "Startup item: " + e.Name
		if e.Command != "" {
			display := e.Command
			if len(display) > 80 {
				display = display[:80] + "..."
			}
			msg += " (" + display + ")"
		}

		if conv.AddEvent(collectionTime, "Collection Time (Startup Configuration)", msg, "startup_item",
			"RR-Collector", "ResponseRay Collector - Startup Items",
			"windows:registry:run", map[string]interface{}{
				"config_type": "Startup",
				"description": e.Name,
				"details":     e.Command,
				"arguments":   "",
				"location":    e.Location,
				"user_id":     e.User,
			}) {
			added++
		}
	}
	return added
}

func processDevices(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		Name         string `json:"name"`
		DeviceID     string `json:"device_id"`
		Manufacturer string `json:"manufacturer"`
		Status       string `json:"status"`
		ClassName    string `json:"class_name"`
		SerialNumber string `json:"serial_number"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("devices.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		deviceDesc := e.Name
		if e.Manufacturer != "" {
			deviceDesc += " (" + e.Manufacturer + ")"
		}
		if e.SerialNumber != "" {
			deviceDesc += " [S/N: " + e.SerialNumber + "]"
		}

		if conv.AddEvent(collectionTime, "Collection Time (Device Attached)", "Device: "+deviceDesc,
			"attached_device", "RR-Collector", "ResponseRay Collector - Attached Devices",
			"windows:registry:usbstor", map[string]interface{}{
				"device_name":  e.Name,
				"device_id":    e.DeviceID,
				"manufacturer": e.Manufacturer,
				"status":       e.Status,
				"class_name":   e.ClassName,
				"serial_num":   e.SerialNumber,
			}) {
			added++
		}
	}
	return added
}

func processUserAccessedData(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		Type     string  `json:"type"`
		Name     string  `json:"name"`
		Path     string  `json:"path"`
		User     string  `json:"user"`
		Modified *string `json:"modified"`
		Size     *int64  `json:"size"`
		Detail   *string `json:"detail"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("user_accessed_data.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		ts := collectionTime
		if e.Modified != nil && *e.Modified != "" {
			ts = *e.Modified
		}

		msg := e.Type + ": " + e.Path
		if e.User != "" {
			msg += " (User: " + e.User + ")"
		}

		attrs := map[string]interface{}{
			"access_type": e.Type,
			"file_path":   e.Path,
			"file_name":   e.Name,
			"user_id":     e.User,
		}
		if e.Size != nil {
			attrs["file_size"] = *e.Size
		}
		if e.Detail != nil {
			attrs["detail"] = *e.Detail
		}

		if conv.AddEvent(ts, "File Access Time", msg, "file_access",
			"RR-Collector", "ResponseRay Collector - User Accessed Data",
			"windows:registry:mrulist", attrs) {
			added++
		}
	}
	return added
}

func processOSConfig(path string, conv *converter.Converter, collectionTime string) int {
	var entries []struct {
		Category string  `json:"category"`
		Name     string  `json:"name"`
		Value    string  `json:"value"`
		Detail   *string `json:"detail"`
	}
	if err := readJSONFile(path, &entries); err != nil {
		progress.Warning(fmt.Sprintf("os_config.json: %v", err))
		return 0
	}

	added := 0
	for _, e := range entries {
		msg := "OS Config: " + e.Name
		if e.Value != "" {
			display := e.Value
			if len(display) > 80 {
				display = display[:80] + "..."
			}
			msg += " = " + display
		}

		attrs := map[string]interface{}{
			"setting": e.Name,
			"value":   e.Value,
			"group":   e.Category,
		}
		if e.Detail != nil {
			attrs["detail"] = *e.Detail
		}

		if conv.AddEvent(collectionTime, "Collection Time (OS Configuration)", msg, "os_config",
			"RR-Collector", "ResponseRay Collector - OS Configuration",
			"ct:os:config_setting", attrs) {
			added++
		}
	}
	return added
}

// ----------- helpers -----------

func readJSONFile(path string, dest interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return nil
}

func splitUser(user string) (userID, domain string) {
	if i := strings.LastIndex(user, "\\"); i >= 0 {
		return user[i+1:], user[:i]
	}
	return user, ""
}

func copyAttrs(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{}, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}
