package registry

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"www.velocidex.com/golang/regparser"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

const windowsEpochDelta = 116444736000000000

func init() {
	extractors.Register(&Extractor{})
}

type Extractor struct{}

func (e *Extractor) Name() string { return "registry" }
func (e *Extractor) Description() string {
	return "Windows Registry hives (ShellBags, UserAssist, USB, ShimCache, BAM, etc.)"
}

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	pattern := `(NTUSER\.DAT|UsrClass\.dat|SAM|SYSTEM|SOFTWARE|SECURITY|Amcache\.hve)$`
	regFiles, err := idx.GetCollectedFiles(pattern, "")
	if err != nil {
		return 0, fmt.Errorf("get registry files: %w", err)
	}
	if len(regFiles) == 0 {
		progress.Warning("No Registry hives with collected content found")
		return 0, nil
	}

	progress.Info(fmt.Sprintf("Processing %d Registry hives with pure-Go parser", len(regFiles)))

	totalEvents := 0
	for i, rf := range regFiles {
		progress.ProgressLine("Registry [%d/%d] %s", i+1, len(regFiles), rf.Filename)

		fpath, cleanup := resolveRegPath(rf)
		if fpath == "" {
			progress.Warning(fmt.Sprintf("Failed to resolve %s", rf.Filename))
			continue
		}
		if cleanup != nil {
			defer cleanup()
		}

		count := e.parseHivePath(fpath, rf.Filename, conv)
		totalEvents += count
	}

	progress.ProgressDone()
	progress.Info(fmt.Sprintf("Registry: %d events extracted", totalEvents))
	return totalEvents, nil
}

func resolveRegPath(rf cache.CollectedFile) (string, func()) {
	if rf.DiskPath != "" {
		return rf.DiskPath, nil
	}
	decoded, err := extractors.GetFileContent(rf)
	if err != nil || len(decoded) == 0 {
		return "", nil
	}
	safe := regexp.MustCompile(`[^\w\-_.]`).ReplaceAllString(rf.Filename, "_")
	tmpPath := filepath.Join(os.TempDir(), "ct_reg_"+safe)
	if err := os.WriteFile(tmpPath, decoded, 0600); err != nil {
		return "", nil
	}
	return tmpPath, func() { os.Remove(tmpPath) }
}

func (e *Extractor) parseHivePath(fpath, filename string, conv *converter.Converter) int {
	fd, err := os.Open(fpath)
	if err != nil {
		progress.Warning(fmt.Sprintf("Failed to open %s: %v", filename, err))
		return 0
	}
	defer fd.Close()

	reg, err := regparser.NewRegistry(fd)
	if err != nil {
		progress.Warning(fmt.Sprintf("Failed to parse registry %s: %v", filename, err))
		return 0
	}

	nameLower := strings.ToLower(filename)
	events := 0

	switch {
	case strings.Contains(nameLower, "ntuser"):
		events += parseNTUser(reg, conv, filename)
	case strings.Contains(nameLower, "usrclass"):
		events += parseUsrClass(reg, conv, filename)
	case nameLower == "sam":
		events += parseSAM(reg, conv, filename)
	case nameLower == "system":
		events += parseSYSTEM(reg, conv, filename)
	case nameLower == "software":
		events += parseSOFTWARE(reg, conv, filename)
	case strings.Contains(nameLower, "amcache"):
		events += parseAmcache(reg, conv, filename)
	}

	return events
}

// --- NTUSER.DAT ---

func parseNTUser(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	events := 0
	events += parseUserAssist(reg, conv, filename)
	events += parseRecentDocs(reg, conv, filename)
	events += parseTypedPaths(reg, conv, filename)
	events += parseRunMRU(reg, conv, filename)
	events += parseTypedURLs(reg, conv, filename)
	events += parseWordWheel(reg, conv, filename)
	events += parseRunKeys(reg, conv, filename, []string{
		"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
		"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
		"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell",
	})
	return events
}

func parseUserAssist(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	events := 0
	uaKey := reg.OpenKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist")
	if uaKey == nil {
		return 0
	}

	for _, guidKey := range uaKey.Subkeys() {
		countKey := openSubkey(guidKey, "Count")
		if countKey == nil {
			continue
		}
		for _, val := range countKey.Values() {
			name := val.ValueName()
			decodedName := rot13(name)
			vd := val.ValueData()
			if vd == nil || len(vd.Data) < 68 {
				continue
			}
			ft := binary.LittleEndian.Uint64(vd.Data[60:68])
			ts := filetimeToISO(ft)
			if ts == "" {
				continue
			}
			if conv.AddEvent(ts, "UserAssist Last Execution",
				"Program executed (UserAssist): "+decodedName,
				"registry_userassist", "CT-Registry",
				"CyberTriage Registry - "+filename,
				"windows:registry:userassist",
				map[string]interface{}{"value_name": decodedName}) {
				events++
			}
		}
	}
	return events
}

func parseRecentDocs(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs")
	if key == nil {
		return 0
	}
	ts := keyTimestamp(key)
	if ts == "" {
		return 0
	}
	if conv.AddEvent(ts, "RecentDocs Key Modified",
		"Recent documents accessed", "registry_recentdocs", "CT-Registry",
		"CyberTriage Registry - "+filename, "windows:registry:recentdocs",
		nil) {
		return 1
	}
	return 0
}

func parseTypedPaths(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
	if key == nil {
		return 0
	}
	ts := keyTimestamp(key)
	if ts == "" {
		return 0
	}
	var paths []string
	for _, v := range key.Values() {
		if strings.HasPrefix(v.ValueName(), "url") {
			vd := v.ValueData()
			if vd != nil && vd.String != "" {
				paths = append(paths, vd.String)
			}
		}
	}
	if len(paths) == 0 {
		return 0
	}
	msg := "Explorer path typed: " + strings.Join(paths, ", ")
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}
	if conv.AddEvent(ts, "TypedPaths Key Modified", msg,
		"registry_typedpaths", "CT-Registry",
		"CyberTriage Registry - "+filename, "windows:registry:typedurls",
		map[string]interface{}{"typed_paths": strings.Join(paths, ", ")}) {
		return 1
	}
	return 0
}

func parseRunMRU(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
	if key == nil {
		return 0
	}
	ts := keyTimestamp(key)
	if ts == "" {
		return 0
	}
	var commands []string
	for _, v := range key.Values() {
		if v.ValueName() != "MRUList" {
			vd := v.ValueData()
			if vd != nil && vd.String != "" {
				commands = append(commands, strings.TrimRight(vd.String, "\\1\x00"))
			}
		}
	}
	if len(commands) == 0 {
		return 0
	}
	if conv.AddEvent(ts, "RunMRU Key Modified",
		"Run command executed: "+commands[0],
		"registry_runmru", "CT-Registry",
		"CyberTriage Registry - "+filename, "windows:registry:mrulist",
		map[string]interface{}{"commands": strings.Join(commands, ", ")}) {
		return 1
	}
	return 0
}

func parseTypedURLs(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Software\\Microsoft\\Internet Explorer\\TypedURLs")
	if key == nil {
		return 0
	}
	ts := keyTimestamp(key)
	if ts == "" {
		return 0
	}
	events := 0
	for _, v := range key.Values() {
		if strings.HasPrefix(v.ValueName(), "url") {
			vd := v.ValueData()
			if vd == nil || vd.String == "" {
				continue
			}
			url := vd.String
			msg := "Browser URL typed: " + url
			if len(msg) > 200 {
				msg = msg[:200] + "..."
			}
			if conv.AddEvent(ts, "TypedURLs Key Modified", msg,
				"registry_typedurls", "CT-Registry",
				"CyberTriage Registry - "+filename, "windows:registry:typedurls",
				map[string]interface{}{"url": url, "entry_number": v.ValueName()}) {
				events++
			}
		}
	}
	return events
}

func parseWordWheel(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery")
	if key == nil {
		return 0
	}
	ts := keyTimestamp(key)
	if ts == "" {
		return 0
	}
	events := 0
	for _, v := range key.Values() {
		name := v.ValueName()
		if name == "MRUListEx" || name == "" {
			continue
		}
		vd := v.ValueData()
		if vd == nil || len(vd.Data) == 0 {
			continue
		}
		query := decodeUTF16LE(vd.Data)
		if query == "" {
			continue
		}
		if conv.AddEvent(ts, "Windows Search Query",
			"Search: "+query, "registry_wordwheel", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:wordwheel",
			map[string]interface{}{"search_query": query}) {
			events++
		}
	}
	return events
}

func parseRunKeys(reg *regparser.Registry, conv *converter.Converter, filename string, keyPaths []string) int {
	events := 0
	for _, kp := range keyPaths {
		key := reg.OpenKey(kp)
		if key == nil {
			continue
		}
		ts := keyTimestamp(key)
		if ts == "" {
			continue
		}
		for _, v := range key.Values() {
			name := v.ValueName()
			if name == "" || strings.EqualFold(name, "(Default)") {
				continue
			}
			vd := v.ValueData()
			val := ""
			if vd != nil {
				val = vd.String
			}
			msg := "Startup item configured: " + name
			if val != "" {
				msg += " (" + val + ")"
			}
			if conv.AddEvent(ts, "Registry Key Modified", msg, "startup_item",
				"CT-Registry", "CyberTriage Registry - "+filename,
				"windows:registry:run", map[string]interface{}{
					"config_type":    "Run/RunOnce",
					"description":    name,
					"details":        val,
					"registry_key":   kp,
					"registry_value": name,
				}) {
				events++
			}
		}
	}
	return events
}

// --- UsrClass.dat ---

func parseUsrClass(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU")
	if key == nil {
		return 0
	}
	events := 0
	recurseShellBags(key, conv, filename, &events, 0)
	return events
}

func recurseShellBags(key *regparser.CM_KEY_NODE, conv *converter.Converter, filename string, events *int, depth int) {
	if depth > 10 {
		return
	}
	ts := keyTimestamp(key)
	if ts != "" {
		name := key.Name()
		if conv.AddEvent(ts, "ShellBag Key Modified",
			"Folder accessed (ShellBag): "+name,
			"registry_shellbag", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:bagmru",
			nil) {
			*events++
		}
	}
	for _, sub := range key.Subkeys() {
		recurseShellBags(sub, conv, filename, events, depth+1)
	}
}

// --- SAM ---

func parseSAM(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	usersKey := reg.OpenKey("SAM\\Domains\\Account\\Users")
	if usersKey == nil {
		return 0
	}
	events := 0
	for _, userKey := range usersKey.Subkeys() {
		name := userKey.Name()
		if strings.EqualFold(name, "Names") {
			continue
		}
		rid := 0
		fmt.Sscanf(name, "%x", &rid)
		ts := keyTimestamp(userKey)
		if ts == "" {
			continue
		}
		msg := fmt.Sprintf("SAM User account (RID: %d)", rid)
		if conv.AddEvent(ts, "SAM User Key Modified", msg,
			"registry_sam_user", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:sam_users",
			map[string]interface{}{"account_rid": rid}) {
			events++
		}
	}
	return events
}

// --- SYSTEM ---

func parseSYSTEM(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	events := 0
	events += parseServices(reg, conv, filename)
	events += parseUSBStor(reg, conv, filename)
	events += parseShimCache(reg, conv, filename)
	events += parseBAM(reg, conv, filename)
	return events
}

func parseServices(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("ControlSet001\\Services")
	if key == nil {
		return 0
	}
	events := 0
	for _, svc := range key.Subkeys() {
		ts := keyTimestamp(svc)
		if ts == "" {
			continue
		}
		imagePath := getValueString(svc, "ImagePath")
		if conv.AddEvent(ts, "Service Key Modified",
			"Service configured: "+svc.Name(),
			"registry_service", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:services",
			map[string]interface{}{"service_name": svc.Name(), "image_path": imagePath}) {
			events++
		}
	}
	return events
}

func parseUSBStor(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("ControlSet001\\Enum\\USBSTOR")
	if key == nil {
		return 0
	}
	events := 0
	for _, devKey := range key.Subkeys() {
		for _, serialKey := range devKey.Subkeys() {
			ts := keyTimestamp(serialKey)
			if ts == "" {
				continue
			}
			if conv.AddEvent(ts, "USB Device Connected",
				fmt.Sprintf("USB storage device: %s (Serial: %s)", devKey.Name(), serialKey.Name()),
				"registry_usb", "CT-Registry",
				"CyberTriage Registry - "+filename, "windows:registry:usbstor",
				map[string]interface{}{
					"device_description": devKey.Name(),
					"serial_number":      serialKey.Name(),
				}) {
				events++
			}
		}
	}
	return events
}

func parseShimCache(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	var appKey *regparser.CM_KEY_NODE
	for _, cs := range []string{"ControlSet001", "CurrentControlSet"} {
		appKey = reg.OpenKey(cs + "\\Control\\Session Manager\\AppCompatCache")
		if appKey != nil {
			break
		}
	}
	if appKey == nil {
		return 0
	}

	var cacheData []byte
	for _, v := range appKey.Values() {
		if v.ValueName() == "AppCompatCache" {
			vd := v.ValueData()
			if vd != nil {
				cacheData = vd.Data
			}
			break
		}
	}
	if len(cacheData) < 16 {
		return 0
	}

	entries := parseShimCacheWin10(cacheData)
	fallbackTS := keyTimestamp(appKey)
	events := 0

	for _, entry := range entries {
		ts := entry.modifiedTime
		if ts == "" {
			ts = fallbackTS
		}
		if ts == "" {
			continue
		}
		fileName := entry.path
		if idx := strings.LastIndex(fileName, "\\"); idx >= 0 {
			fileName = fileName[idx+1:]
		}
		if conv.AddEvent(ts, "ShimCache Last Modified Time",
			"ShimCache: "+fileName,
			"registry_shimcache", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:appcompatcache",
			map[string]interface{}{
				"file_path": entry.path,
				"file_name": fileName,
			}) {
			events++
		}
	}
	return events
}

type shimEntry struct {
	path         string
	modifiedTime string
}

func parseShimCacheWin10(data []byte) []shimEntry {
	var entries []shimEntry
	offset := 0x30
	for offset < len(data)-14 {
		sig := binary.LittleEndian.Uint32(data[offset : offset+4])
		if sig != 0x10 {
			offset += 4
			continue
		}
		entrySize := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		if entrySize == 0 || entrySize > 0x10000 {
			break
		}
		pathLen := binary.LittleEndian.Uint16(data[offset+12 : offset+14])
		if pathLen == 0 || pathLen > 2000 {
			offset += 4
			continue
		}
		pathStart := offset + 14
		pathEnd := pathStart + int(pathLen)
		if pathEnd > len(data) {
			break
		}
		path := decodeUTF16LE(data[pathStart:pathEnd])
		var modTime string
		timeOff := pathEnd
		if timeOff+8 <= len(data) {
			ft := binary.LittleEndian.Uint64(data[timeOff : timeOff+8])
			modTime = filetimeToISO(ft)
		}
		if path != "" {
			entries = append(entries, shimEntry{path: path, modifiedTime: modTime})
		}
		offset += int(entrySize)
	}
	return entries
}

func parseBAM(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	bamPaths := []string{
		"ControlSet001\\Services\\bam\\State\\UserSettings",
		"ControlSet001\\Services\\bam\\UserSettings",
		"ControlSet001\\Services\\dam\\State\\UserSettings",
		"ControlSet001\\Services\\dam\\UserSettings",
	}
	events := 0
	for _, bp := range bamPaths {
		key := reg.OpenKey(bp)
		if key == nil {
			continue
		}
		for _, userKey := range key.Subkeys() {
			userSID := userKey.Name()
			for _, val := range userKey.Values() {
				valName := val.ValueName()
				if valName == "Version" || valName == "SequenceNumber" || valName == "" {
					continue
				}
				vd := val.ValueData()
				if vd == nil || len(vd.Data) < 8 {
					continue
				}
				ft := binary.LittleEndian.Uint64(vd.Data[0:8])
				ts := filetimeToISO(ft)
				if ts == "" {
					continue
				}
				fileName := valName
				if idx := strings.LastIndex(fileName, "\\"); idx >= 0 {
					fileName = fileName[idx+1:]
				}
				if conv.AddEvent(ts, "BAM Execution Time",
					"BAM execution: "+fileName,
					"registry_bam", "CT-Registry",
					"CyberTriage Registry - "+filename, "windows:registry:bam",
					map[string]interface{}{
						"file_path": valName,
						"file_name": fileName,
						"user_sid":  userSID,
					}) {
					events++
				}
			}
		}
	}
	return events
}

// --- SOFTWARE ---

func parseSOFTWARE(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	events := 0
	events += parseUninstall(reg, conv, filename)
	events += parseNetworkList(reg, conv, filename)
	events += parseDefenderExclusions(reg, conv, filename)
	events += parseWinlogon(reg, conv, filename)
	events += parseRunKeys(reg, conv, filename, []string{
		"Microsoft\\Windows\\CurrentVersion\\Run",
		"Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"Microsoft\\Windows\\CurrentVersion\\RunServices",
		"Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
		"Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
	})
	return events
}

func parseUninstall(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Microsoft\\Windows\\CurrentVersion\\Uninstall")
	if key == nil {
		return 0
	}
	events := 0
	for _, prog := range key.Subkeys() {
		ts := keyTimestamp(prog)
		if ts == "" {
			continue
		}
		displayName := getValueString(prog, "DisplayName")
		if displayName == "" {
			displayName = prog.Name()
		}
		publisher := getValueString(prog, "Publisher")
		msg := "Software: " + displayName
		if publisher != "" {
			msg += " by " + publisher
		}
		if conv.AddEvent(ts, "Software Installed/Modified", msg,
			"registry_software", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:uninstall",
			map[string]interface{}{"software_name": displayName, "publisher": publisher}) {
			events++
		}
	}
	return events
}

func parseNetworkList(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")
	if key == nil {
		return 0
	}
	events := 0
	for _, profile := range key.Subkeys() {
		profileName := getValueString(profile, "ProfileName")
		if profileName == "" {
			profileName = profile.Name()
		}
		category := getValueUint(profile, "Category")
		catStr := "Unknown"
		switch category {
		case 0:
			catStr = "Public"
		case 1:
			catStr = "Private"
		case 2:
			catStr = "Domain"
		}

		ts := keyTimestamp(profile)
		if ts == "" {
			continue
		}
		if conv.AddEvent(ts, "Network Profile Modified",
			fmt.Sprintf("Network profile: %s (%s)", profileName, catStr),
			"registry_networklist", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:network_profile",
			map[string]interface{}{
				"profile_name": profileName,
				"category":     catStr,
			}) {
			events++
		}
	}
	return events
}

func parseDefenderExclusions(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	events := 0
	for _, exType := range []string{"Paths", "Extensions", "Processes"} {
		key := reg.OpenKey("Microsoft\\Windows Defender\\Exclusions\\" + exType)
		if key == nil {
			continue
		}
		ts := keyTimestamp(key)
		if ts == "" {
			continue
		}
		for _, v := range key.Values() {
			exVal := v.ValueName()
			if exVal == "" {
				continue
			}
			msg := fmt.Sprintf("Defender exclusion (%s): %s", exType, exVal)
			if conv.AddEvent(ts, "Defender Exclusion Added", msg,
				"registry_defender_exclusion", "CT-Registry",
				"CyberTriage Registry - "+filename, "windows:registry:defender_exclusion",
				map[string]interface{}{
					"exclusion_type":  strings.ToLower(exType),
					"exclusion_value": exVal,
				}) {
				events++
			}
		}
	}
	return events
}

func parseWinlogon(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
	if key == nil {
		return 0
	}
	ts := keyTimestamp(key)
	if ts == "" {
		return 0
	}
	events := 0

	shell := getValueString(key, "Shell")
	if shell != "" {
		suspicious := !strings.EqualFold(strings.TrimSpace(shell), "explorer.exe")
		suffix := ""
		if suspicious {
			suffix = " [SUSPICIOUS]"
		}
		if conv.AddEvent(ts, "Winlogon Key Modified",
			"Winlogon Shell: "+shell+suffix,
			"registry_winlogon", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:winlogon",
			map[string]interface{}{"value_name": "Shell", "value_data": shell, "is_suspicious": suspicious}) {
			events++
		}
	}

	userinit := getValueString(key, "Userinit")
	if userinit != "" {
		lower := strings.ToLower(strings.TrimSpace(userinit))
		suspicious := lower != "c:\\windows\\system32\\userinit.exe," &&
			lower != "userinit.exe," &&
			lower != "c:\\windows\\system32\\userinit.exe" &&
			lower != "userinit.exe"
		suffix := ""
		if suspicious {
			suffix = " [SUSPICIOUS]"
		}
		if conv.AddEvent(ts, "Winlogon Key Modified",
			"Winlogon Userinit: "+userinit+suffix,
			"registry_winlogon", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:winlogon",
			map[string]interface{}{"value_name": "Userinit", "value_data": userinit, "is_suspicious": suspicious}) {
			events++
		}
	}

	return events
}

// --- Amcache.hve ---

func parseAmcache(reg *regparser.Registry, conv *converter.Converter, filename string) int {
	key := reg.OpenKey("Root\\InventoryApplicationFile")
	if key == nil {
		return 0
	}
	events := 0
	for _, fileKey := range key.Subkeys() {
		ts := keyTimestamp(fileKey)
		if ts == "" {
			continue
		}
		name := getValueString(fileKey, "Name")
		if name == "" {
			name = fileKey.Name()
		}
		if conv.AddEvent(ts, "Amcache Entry Created",
			"Program evidence (Amcache): "+name,
			"registry_amcache", "CT-Registry",
			"CyberTriage Registry - "+filename, "windows:registry:amcache",
			map[string]interface{}{"program_name": name}) {
			events++
		}
	}
	return events
}

// --- Helpers ---

func openSubkey(parent *regparser.CM_KEY_NODE, name string) *regparser.CM_KEY_NODE {
	for _, sub := range parent.Subkeys() {
		if strings.EqualFold(sub.Name(), name) {
			return sub
		}
	}
	return nil
}

func keyTimestamp(key *regparser.CM_KEY_NODE) string {
	lwt := key.LastWriteTime()
	if lwt == nil {
		return ""
	}
	t := lwt.Time
	if t.IsZero() || t.Year() < 1970 || t.Year() > 2100 {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func getValueString(key *regparser.CM_KEY_NODE, name string) string {
	for _, v := range key.Values() {
		if strings.EqualFold(v.ValueName(), name) {
			vd := v.ValueData()
			if vd != nil && vd.String != "" {
				return strings.TrimRight(vd.String, "\x00")
			}
			return ""
		}
	}
	return ""
}

func getValueUint(key *regparser.CM_KEY_NODE, name string) uint64 {
	for _, v := range key.Values() {
		if strings.EqualFold(v.ValueName(), name) {
			vd := v.ValueData()
			if vd != nil {
				return vd.Uint64
			}
			return 0
		}
	}
	return 0
}

func rot13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		}
		return r
	}, s)
}

func filetimeToISO(ft uint64) string {
	if ft == 0 || ft < windowsEpochDelta {
		return ""
	}
	ns := int64(ft-windowsEpochDelta) * 100
	t := time.Unix(0, ns).UTC()
	if t.Year() < 1970 || t.Year() > 2100 {
		return ""
	}
	return t.Format("2006-01-02T15:04:05.000Z")
}

func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// Trim trailing nulls
	for len(data) >= 2 && data[len(data)-1] == 0 && data[len(data)-2] == 0 {
		data = data[:len(data)-2]
	}
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	var buf bytes.Buffer
	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch == 0 {
			break
		}
		buf.WriteRune(rune(ch))
	}
	return buf.String()
}
