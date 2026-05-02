package converter

import (
	"fmt"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// CollectionTool converters
// ---------------------------------------------------------------------------

func (c *Converter) ConvertProcessCollection(a Artifact) bool {
	ts := EpochMsFromAny(a["startTime"])
	if ts == "" {
		return false
	}
	name := GetStr(a, "name")
	if name == "" {
		name = "unknown"
	}
	path := GetStr(a, "path")
	args := GetStr(a, "args")
	userID := GetStr(a, "userID")
	userDomain := GetStr(a, "userDomain")

	si := GetSourceInfo(a)
	subType := "Registry"
	if si != nil {
		if s := GetStr(si, "subType"); s != "" {
			subType = s
		}
	}

	msg := "Program executed: " + name
	if args != "" {
		msg += " " + args
	}
	if userID != "" {
		u := userID
		if userDomain != "" {
			u = userDomain + "\\" + userID
		}
		msg += " (User: " + u + ")"
	}

	return c.AddEventFromArtifact(a, ts, "Program Execution Time", msg, "process_execution",
		"CT-Registry", "CyberTriage CollectionTool - "+subType,
		"windows:registry:userassist", map[string]interface{}{
			"process_name":     name,
			"process_path":     path,
			"raw_path_data":    GetStr(a, "rawPathData"),
			"command_line":     args,
			"user_id":          userID,
			"user_domain":      userDomain,
			"user_sid":         GetStr(a, "userSID"),
			"observation_type": GetStr(a, "observationType"),
			"ppid":             GetStr(a, "ppid"),
			"parent_path":      GetStr(a, "parentPath"),
			"elevated_admin":   GetStr(a, "elevatedAdminPriv"),
			"is_service":       GetStr(a, "isService"),
		})
}

func (c *Converter) ConvertConfigItem(a Artifact) bool {
	si := GetSourceInfo(a)
	if si == nil {
		return false
	}
	ts := EpochMsFromAny(si["lastWriteTime"])
	if ts == "" {
		return false
	}
	itemType := GetStr(a, "type")
	if itemType == "" {
		itemType = "unknown"
	}
	desc := GetStr(a, "description")
	args := GetStr(a, "args")

	msg := "Startup item configured: " + itemType
	if desc != "" {
		msg += " - " + desc
	}
	if args != "" {
		msg += " (" + args + ")"
	}

	return c.AddEventFromArtifact(a, ts, "Registry Key Modified", msg, "startup_item",
		"CT-Registry", "CyberTriage CollectionTool - Startup Programs",
		"windows:registry:run", map[string]interface{}{
			"config_type":    itemType,
			"description":    desc,
			"details":        GetStr(a, "details"),
			"arguments":      args,
			"user_id":        GetStr(a, "userID"),
			"registry_key":   GetStr(si, "keyName"),
			"registry_value": GetStr(si, "valueName"),
		})
}

func (c *Converter) ConvertLogonDataCollection(a Artifact) bool {
	si := GetSourceInfo(a)
	if si == nil {
		return false
	}
	ts := EpochMsFromAny(si["lastWriteTime"])
	if ts == "" {
		return false
	}
	entries := GetStr(a, "remoteHostName")
	username := GetStr(a, "remoteUser")
	remoteDomain := GetStr(a, "remoteDomain")

	msg := "RDP connection to " + entries
	if username != "" {
		u := username
		if remoteDomain != "" {
			u = remoteDomain + "\\" + username
		}
		msg += " as " + u
	}

	return c.AddEventFromArtifact(a, ts, "RDP Connection Time", msg, "rdp_connection",
		"CT-Registry", "CyberTriage CollectionTool - Terminal Server Client",
		"windows:registry:mstsc:connection", map[string]interface{}{
			"entries":       entries,
			"username":      username,
			"key_path":      GetStr(si, "keyName"),
			"remote_domain": remoteDomain,
			"local_user":    GetStr(a, "userID"),
			"user_sid":      GetStr(a, "userSID"),
		})
}

func (c *Converter) ConvertUserAccessedData(a Artifact) bool {
	ts := EpochMsFromAny(a["maxLastAccessDate"])
	if ts == "" {
		return false
	}
	path := GetStr(a, "path")
	userID := GetStr(a, "userID")
	userDomain := GetStr(a, "userDomain")

	si := GetSourceInfo(a)
	subType := "MRU"
	if si != nil {
		if s := GetStr(si, "subType"); s != "" {
			subType = s
		}
	}

	msg := "File accessed: " + path
	if userID != "" {
		u := userID
		if userDomain != "" {
			u = userDomain + "\\" + userID
		}
		msg += " (User: " + u + ")"
	}

	return c.AddEventFromArtifact(a, ts, "File Access Time", msg, "file_access",
		"CT-Registry", "CyberTriage CollectionTool - "+subType,
		"windows:registry:mrulist", map[string]interface{}{
			"file_path":   path,
			"user_id":     userID,
			"user_domain": userDomain,
			"user_sid":    GetStr(a, "userSID"),
		})
}

func (c *Converter) ConvertNetworkConnectionCollection(a Artifact) bool {
	si := GetSourceInfo(a)
	if si == nil {
		return false
	}
	ts := EpochMsFromAny(si["lastWriteTime"])
	if ts == "" {
		return false
	}
	remoteHost := GetStr(a, "remoteHostName")
	remoteShare := GetStr(a, "remoteShareName")

	msg := fmt.Sprintf("Network share mounted: \\\\%s\\%s", remoteHost, remoteShare)

	return c.AddEventFromArtifact(a, ts, "Network Share Mount Time", msg, "network_share",
		"CT-Registry", "CyberTriage CollectionTool - MountPoints2",
		"windows:registry:mountpoints2", map[string]interface{}{
			"remote_host_name":  remoteHost,
			"remote_share_name": remoteShare,
			"user_id":           GetStr(a, "userID"),
			"user_sid":          GetStr(a, "userSID"),
		})
}

func (c *Converter) ConvertUserAccount(a Artifact) bool {
	ts := EpochMsFromAny(a["dateCreated"])
	if ts == "" {
		ts = GetStr(a, "lastLoginDate")
	}
	if ts == "" {
		return false
	}
	username := GetStr(a, "userID")
	userDomain := GetStr(a, "userDomain")
	userSID := GetStr(a, "userSID")
	accountType := GetStr(a, "accountType")
	adminPriv := GetStr(a, "adminPriv")

	var accountRID interface{}
	if userSID != "" {
		parts := strings.Split(userSID, "-")
		if len(parts) > 0 {
			if rid, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
				accountRID = rid
			}
		}
	}

	var loginCount interface{}
	if lc := GetStr(a, "loginCount"); lc != "" {
		if n, err := strconv.Atoi(lc); err == nil {
			loginCount = n
		}
	}

	u := username
	if userDomain != "" {
		u = userDomain + "\\" + username
	}
	msg := "User account: " + u
	if accountType != "" {
		msg += " (" + accountType + ")"
	}
	if adminPriv == "true" || adminPriv == "domain" {
		msg += " [ADMIN]"
	}

	return c.AddEventFromArtifact(a, ts, "Account Created/Modified", msg, "account_created",
		"CT-SAM", "CyberTriage CollectionTool - User Account",
		"windows:registry:sam_users", map[string]interface{}{
			"username":       username,
			"account_rid":    accountRID,
			"login_count":    loginCount,
			"user_domain":    userDomain,
			"user_sid":       userSID,
			"account_type":   accountType,
			"account_status": GetStr(a, "accountStatus"),
			"admin_priv":     adminPriv,
			"home_dir":       GetStr(a, "userHomeDir"),
		})
}

// ---------------------------------------------------------------------------
// SystemAPI converters
// ---------------------------------------------------------------------------

func (c *Converter) ConvertProcessSystemAPI(a Artifact) bool {
	ts := EpochMsFromAny(a["startTime"])
	if ts == "" {
		return false
	}
	name := GetStr(a, "name")
	if name == "" {
		name = "unknown"
	}
	pid := GetStr(a, "pid")
	args := GetStr(a, "args")

	msg := fmt.Sprintf("Process running: %s (PID: %s)", name, pid)
	if args != "" {
		msg += " " + args
	}

	return c.AddEventFromArtifact(a, ts, "Process Start Time", msg, "session_logon",
		"CT-Memory", "CyberTriage SystemAPI - Process List",
		"windows:tasks:job", map[string]interface{}{
			"process_name": name,
			"process_path": GetStr(a, "path"),
			"pid":          pid,
			"command_line": args,
			"user_id":      GetStr(a, "userID"),
		})
}

func (c *Converter) ConvertLogonDataSystemAPI(a Artifact) bool {
	ts := EpochMsFromAny(a["time"])
	if ts == "" {
		return false
	}
	userID := GetStr(a, "userID")
	userDomain := GetStr(a, "userDomain")
	logonType := GetStr(a, "logonType")

	u := userID
	if userDomain != "" {
		u = userDomain + "\\" + userID
	}
	msg := "User logged in: " + u
	if logonType != "" {
		msg += " (Type: " + logonType + ")"
	}

	return c.AddEventFromArtifact(a, ts, "Logon Session Time", msg, "user_login",
		"CT-Memory", "CyberTriage SystemAPI - Logon Sessions",
		"windows:evtx:record", map[string]interface{}{
			"userID":     userID,
			"userDomain": userDomain,
			"logonType":  logonType,
			"logonID":    GetStr(a, "logonID"),
		})
}

func (c *Converter) ConvertNetworkConnectionSystemAPI(a Artifact) bool {
	ts := EpochMsFromAny(a["time"])
	if ts == "" {
		return false
	}
	localIP := GetStr(a, "localIP")
	localPort := GetStr(a, "localPort")
	remoteIP := GetStr(a, "remoteIP")
	remotePort := GetStr(a, "remotePort")
	connType := GetStr(a, "connectionType")

	msg := fmt.Sprintf("Network connection: %s:%s → %s:%s", localIP, localPort, remoteIP, remotePort)
	if connType != "" {
		msg += " (" + connType + ")"
	}

	return c.AddEventFromArtifact(a, ts, "Connection Observed", msg, "network_connection",
		"CT-Memory", "CyberTriage SystemAPI - Network Connections",
		"windows:network:connection", map[string]interface{}{
			"local_ip":         localIP,
			"local_port":       localPort,
			"remote_ip":        remoteIP,
			"remote_port":      remotePort,
			"connection_type":  connType,
			"pid":              GetStr(a, "pid"),
			"state":            GetStr(a, "state"),
			"direction":        GetStr(a, "direction"),
			"local_host_name":  GetStr(a, "localHostName"),
			"local_domain":     GetStr(a, "localDomain"),
			"remote_domain":    GetStr(a, "remoteDomain"),
			"remote_host_name": GetStr(a, "remoteHostName"),
		})
}

// ---------------------------------------------------------------------------
// TSK / MFT converters
// ---------------------------------------------------------------------------

func (c *Converter) ConvertFileMFT(a Artifact) int {
	added := 0
	fullPath := GetStr(a, "fullPath")
	if fullPath == "" {
		fullPath = GetStr(a, "path")
	}
	filename := GetStr(a, "fileName")
	metaType := GetStr(a, "metaType")
	if metaType == "" {
		metaType = "File"
	}

	baseAttrs := map[string]interface{}{
		"file_path":           fullPath,
		"file_name":           filename,
		"file_size":           a["fileSize"],
		"meta_type":           metaType,
		"file_content_status": a["fileContentStatus"],
		"md5":                 a["md5hash"],
		"sha1":                a["sha1hash"],
		"sha256":              a["sha256hash"],
		"imphash":             a["imphash"],
		"signature":           a["Signature"],
		"score":               a["score"],
		"score_description":   a["scoreDescription"],
		"user_sid":            a["userSID"],
		"is_deleted":          a["isDeleted"],
		"is_name_del":         a["isNameDel"],
		"file_mime_type":      a["fileMimeType"],
		"volume_offset":       a["volumeOffset"],
		"meta_data_addr":      a["metaDataAddr"],
	}

	// Extract PE header info if available
	if peInfo := GetMap(a, "peHeaderInfo"); peInfo != nil {
		baseAttrs["pe_company"] = GetStr(peInfo, "companyName")
		baseAttrs["pe_product"] = GetStr(peInfo, "productName")
		baseAttrs["pe_description"] = GetStr(peInfo, "fileDescription")
		baseAttrs["pe_original_filename"] = GetStr(peInfo, "originalFilename")
		baseAttrs["pe_imphash"] = GetStr(peInfo, "imphash")
	}
	ExtractAnalysisAttrs(a, baseAttrs)

	hasHashes := GetStr(a, "md5hash") != "" || GetStr(a, "sha1hash") != "" || GetStr(a, "sha256hash") != ""
	prefix := "File"
	if metaType == "Dir" {
		prefix = "Directory"
	} else if hasHashes {
		prefix = "File (hashed)"
	}

	siFields := []struct{ field, desc string }{
		{"dateModified", "File Modified"},
		{"dateCreated", "File Created"},
		{"dateAccessed", "File Accessed"},
		{"dateChanged", "MFT Entry Changed"},
	}
	for _, f := range siFields {
		ts := EpochMsFromAny(a[f.field])
		if ts == "" {
			continue
		}
		cp := copyAttrs(baseAttrs)
		if c.AddEvent(ts, f.desc, prefix+": "+fullPath, "file_timeline",
			"CT-MFT", "CyberTriage MFT - $STANDARD_INFORMATION",
			"fs:stat:ntfs:$standard_information", cp) {
			added++
		}
	}

	fnFields := []struct{ field, desc string }{
		{"fn_dateModified", "File Modified ($FN)"},
		{"fn_dateCreated", "File Created ($FN)"},
		{"fn_dateAccessed", "File Accessed ($FN)"},
		{"fn_dateChanged", "MFT Entry Changed ($FN)"},
	}
	for _, f := range fnFields {
		ts := EpochMsFromAny(a[f.field])
		if ts == "" {
			continue
		}
		cp := copyAttrs(baseAttrs)
		cp["timestompNote"] = "Compare with SI timestamps for timestomping detection"
		if c.AddEvent(ts, f.desc, prefix+" ($FN): "+fullPath, "file_timeline_fn",
			"CT-MFT", "CyberTriage MFT - $FILE_NAME",
			"fs:stat:ntfs:$file_name", cp) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Amcache / Installed Programs / TaskCache
// ---------------------------------------------------------------------------

func (c *Converter) ConvertAmcacheEntry(e Artifact) bool {
	ts := GetStr(e, "link_date_iso")
	tsDesc := "PE Link Date"
	if ts == "" {
		ts = GetStr(e, "key_timestamp")
		tsDesc = "Amcache Key Modified"
	}
	if ts == "" {
		return false
	}
	name := GetStr(e, "Name")
	if name == "" {
		name = GetStr(e, "key_name")
	}
	if name == "" {
		name = "unknown"
	}
	publisher := GetStr(e, "Publisher")
	product := GetStr(e, "ProductName")

	msg := "Amcache: " + name
	if publisher != "" {
		msg += " (" + publisher + ")"
	} else if product != "" {
		msg += " (" + product + ")"
	}

	return c.AddEvent(ts, tsDesc, msg, "amcache_entry",
		"CT-Amcache", "CyberTriage Amcache - Application Execution",
		"windows:registry:amcache", map[string]interface{}{
			"sha1_hash":       e["sha1_hash"],
			"file_path":       firstNonEmpty(GetStr(e, "LowerCaseLongPath"), GetStr(e, "FullPath")),
			"file_name":       firstNonEmpty(GetStr(e, "Name"), GetStr(e, "OriginalFileName")),
			"publisher":       publisher,
			"product_name":    product,
			"product_version": firstNonEmpty(GetStr(e, "ProductVersion"), GetStr(e, "Version")),
			"program_id":      e["ProgramId"],
		})
}

func (c *Converter) ConvertInstalledProgram(e Artifact) bool {
	ts := GetStr(e, "install_date_iso")
	if ts == "" {
		ts = GetStr(e, "key_timestamp")
	}
	if ts == "" {
		return false
	}
	name := GetStr(e, "Name")
	if name == "" {
		name = GetStr(e, "key_name")
	}
	if name == "" {
		name = "Unknown Program"
	}
	publisher := GetStr(e, "Publisher")
	version := GetStr(e, "Version")

	msg := "Installed Program: " + name
	if version != "" {
		msg += " v" + version
	}
	if publisher != "" {
		msg += " by " + publisher
	}

	return c.AddEvent(ts, "Program Install Date", msg, "installed_program",
		"CT-Amcache", "CyberTriage Amcache - Installed Programs",
		"windows:registry:amcache:inventory_application", map[string]interface{}{
			"program_name":     name,
			"publisher":        publisher,
			"version":          version,
			"install_path":     e["RootDirPath"],
			"uninstall_string": e["UninstallString"],
			"msi_product_code": e["MsiProductCode"],
			"program_id":       e["ProgramId"],
		})
}

func (c *Converter) ConvertTaskCacheEntry(e Artifact) bool {
	ts := GetStr(e, "launch_time")
	tsDesc := "Task Last Launch Time"
	if ts == "" {
		ts = GetStr(e, "last_written_time")
		tsDesc = "Task Cache Entry Modified"
	}
	if ts == "" {
		return false
	}
	taskName := GetStr(e, "task_name")
	taskID := GetStr(e, "task_identifier")
	msg := "Scheduled Task: " + taskName
	if taskName == "" {
		msg = "Scheduled Task: " + taskID
	}

	return c.AddEvent(ts, tsDesc, msg, "scheduled_task",
		"CT-Registry", "CyberTriage Registry - Task Scheduler Cache",
		"task_scheduler:task_cache:entry", map[string]interface{}{
			"task_name":            taskName,
			"task_identifier":      taskID,
			"key_path":             e["key_path"],
			"last_written_time":    e["last_written_time"],
			"last_registered_time": e["last_registered_time"],
			"launch_time":          e["launch_time"],
		})
}

// ---------------------------------------------------------------------------
// SRUM converters
// ---------------------------------------------------------------------------

func (c *Converter) ConvertSRUMApplicationUsage(e Artifact) bool {
	ts := GetStr(e, "timestamp")
	if ts == "" {
		return false
	}
	application := GetStr(e, "application")
	if application == "" {
		application = "Unknown"
	}
	appName := extractAppName(application)

	fgCycles := GetInt64(e, "foreground_cycle_time")
	bgCycles := GetInt64(e, "background_cycle_time")
	totalCycles := fgCycles + bgCycles

	msg := "SRUM: " + appName
	if totalCycles > 0 {
		secs := float64(totalCycles) / 10_000_000
		if secs > 3600 {
			msg += fmt.Sprintf(" (CPU: %.1fh)", secs/3600)
		} else if secs > 60 {
			msg += fmt.Sprintf(" (CPU: %.1fm)", secs/60)
		} else {
			msg += fmt.Sprintf(" (CPU: %.0fs)", secs)
		}
	}

	return c.AddEvent(ts, "SRUM Application Usage Recorded", msg, "srum_application",
		"CT-SRUM", "CyberTriage SRUM - Application Resource Usage",
		"windows:srum:application_usage", map[string]interface{}{
			"application":              application,
			"identifier":               e["auto_inc_id"],
			"user_identifier":          GetStr(e, "user_sid"),
			"foreground_cycle_time":    fgCycles,
			"background_cycle_time":    bgCycles,
			"foreground_bytes_read":    e["foreground_bytes_read"],
			"foreground_bytes_written": e["foreground_bytes_written"],
			"background_bytes_read":    e["background_bytes_read"],
			"background_bytes_written": e["background_bytes_written"],
		})
}

func (c *Converter) ConvertSRUMNetworkConnectivity(e Artifact) bool {
	ts := GetStr(e, "timestamp")
	if ts == "" {
		return false
	}
	application := GetStr(e, "application")
	if application == "" {
		application = "Unknown"
	}
	ifaceType := GetStr(e, "interface_type")
	if ifaceType == "" {
		ifaceType = "Unknown"
	}
	connTime := GetInt64(e, "connected_time")
	appName := extractAppName(application)

	msg := fmt.Sprintf("SRUM Network: %s via %s", appName, ifaceType)
	if connTime > 0 {
		if connTime >= 3600 {
			msg += fmt.Sprintf(" (%.1fh connected)", float64(connTime)/3600)
		} else if connTime >= 60 {
			msg += fmt.Sprintf(" (%.0fm connected)", float64(connTime)/60)
		} else {
			msg += fmt.Sprintf(" (%ds connected)", connTime)
		}
	}

	return c.AddEvent(ts, "SRUM Network Connectivity Recorded", msg, "srum_network",
		"CT-SRUM", "CyberTriage SRUM - Network Connectivity",
		"windows:srum:network_connectivity", map[string]interface{}{
			"application":     application,
			"identifier":      e["auto_inc_id"],
			"interface_luid":  e["interface_luid"],
			"connected_time":  connTime,
			"user_identifier": GetStr(e, "user_sid"),
			"interface_type":  ifaceType,
		})
}

func (c *Converter) ConvertSRUMNetworkUsage(e Artifact) bool {
	ts := GetStr(e, "timestamp")
	if ts == "" {
		return false
	}
	application := GetStr(e, "application")
	if application == "" {
		application = "Unknown"
	}
	bytesIn := GetInt64(e, "bytes_received")
	bytesOut := GetInt64(e, "bytes_sent")
	bytesTotal := bytesIn + bytesOut
	if bytesTotal == 0 {
		return false
	}
	appName := extractAppName(application)
	msg := fmt.Sprintf("SRUM Data: %s - In:%s Out:%s", appName, FormatBytes(bytesIn), FormatBytes(bytesOut))

	return c.AddEvent(ts, "SRUM Network Data Usage Recorded", msg, "srum_network_data",
		"CT-SRUM", "CyberTriage SRUM - Network Data Usage",
		"windows:srum:network_usage", map[string]interface{}{
			"application":     application,
			"identifier":      e["auto_inc_id"],
			"bytes_received":  bytesIn,
			"bytes_sent":      bytesOut,
			"bytes_total":     bytesTotal,
			"user_identifier": GetStr(e, "user_sid"),
		})
}

// ---------------------------------------------------------------------------
// Timeline converters
// ---------------------------------------------------------------------------

func (c *Converter) ConvertTimelineGeneric(e Artifact) bool {
	ts := GetStr(e, "timestamp")
	if ts == "" {
		return false
	}
	application := GetStr(e, "application")
	if application == "" {
		application = "Unknown"
	}
	actType := GetInt(e, "activity_type")
	actTypeStr := GetStr(e, "activity_type_str")
	if actTypeStr == "" {
		actTypeStr = fmt.Sprintf("Type-%d", actType)
	}
	tag := GetStr(e, "tag")

	msg := "Timeline: " + actTypeStr + " - " + application
	if tag != "" {
		msg += " (" + tag + ")"
	}

	tsDesc := "Windows Timeline Activity"
	switch actType {
	case 5:
		tsDesc = "File/Document Opened"
	case 10:
		tsDesc = "Clipboard Activity"
	case 11:
		tsDesc = "Settings Changed"
	case 16:
		tsDesc = "Application Launched"
	}

	return c.AddEvent(ts, tsDesc, msg, "timeline_activity",
		"CT-Timeline", "CyberTriage Windows Timeline",
		"windows:timeline:generic", map[string]interface{}{
			"application":         application,
			"package_identifier":  GetStr(e, "package_name"),
			"activity_identifier": GetStr(e, "activity_id"),
			"activity_type":       actType,
			"tag":                 tag,
		})
}

func (c *Converter) ConvertTimelineUserEngaged(e Artifact) bool {
	ts := GetStr(e, "timestamp")
	if ts == "" {
		return false
	}
	application := GetStr(e, "application")
	if application == "" {
		application = "Unknown"
	}
	duration := GetInt(e, "duration_seconds")
	msg := "User Engaged: " + application
	if duration > 0 {
		if duration >= 3600 {
			msg += fmt.Sprintf(" (%.1fh)", float64(duration)/3600)
		} else if duration >= 60 {
			msg += fmt.Sprintf(" (%.1fm)", float64(duration)/60)
		} else {
			msg += fmt.Sprintf(" (%ds)", duration)
		}
	}

	return c.AddEvent(ts, "User Engagement Started", msg, "timeline_engaged",
		"CT-Timeline", "CyberTriage Windows Timeline - User Engaged",
		"windows:timeline:user_engaged", map[string]interface{}{
			"application":             application,
			"package_identifier":      GetStr(e, "package_name"),
			"active_duration_seconds": duration,
		})
}

// ---------------------------------------------------------------------------
// UAL converters
// ---------------------------------------------------------------------------

func (c *Converter) ConvertUALClientAccess(e Artifact) bool {
	ts := GetStr(e, "timestamp")
	if ts == "" {
		return false
	}
	address := GetStr(e, "address")
	if address == "" {
		address = "Unknown"
	}
	username := GetStr(e, "username")
	roleName := GetStr(e, "role_name")
	if roleName == "" {
		roleName = "Unknown Service"
	}
	totalAccesses := GetInt(e, "total_accesses")

	userShort := username
	if i := strings.LastIndex(username, "\\"); i >= 0 {
		userShort = username[i+1:]
	}
	msg := fmt.Sprintf("UAL: %s from %s -> %s", userShort, address, roleName)
	if username == "" {
		msg = fmt.Sprintf("UAL: Anonymous from %s -> %s", address, roleName)
	}
	if totalAccesses > 1 {
		msg += fmt.Sprintf(" (%d total accesses)", totalAccesses)
	}

	return c.AddEvent(ts, "Client Access Recorded", msg, "ual_client_access",
		"CT-UAL", "CyberTriage User Access Logging - Clients",
		"windows:user_access_logging:clients", map[string]interface{}{
			"source_address":  address,
			"username":        username,
			"client_name":     GetStr(e, "client_name"),
			"role_identifier": GetStr(e, "role_guid"),
			"role_name":       roleName,
			"access_count":    totalAccesses,
		})
}

func (c *Converter) ConvertUALDNSQuery(e Artifact) bool {
	ts := GetStr(e, "timestamp")
	if ts == "" {
		return false
	}
	clientAddr := GetStr(e, "client_address")
	if clientAddr == "" {
		clientAddr = "Unknown"
	}
	hostname := GetStr(e, "hostname")
	if hostname == "" {
		hostname = "Unknown"
	}

	return c.AddEvent(ts, "DNS Query Recorded",
		fmt.Sprintf("DNS Query: %s -> %s", clientAddr, hostname),
		"ual_dns_query",
		"CT-UAL", "CyberTriage User Access Logging - DNS",
		"windows:user_access_logging:dns", map[string]interface{}{
			"client_address": clientAddr,
			"hostname":       hostname,
		})
}

// ---------------------------------------------------------------------------
// System State / Memory converters
// ---------------------------------------------------------------------------

func (c *Converter) ConvertRunningProcess(a Artifact, collectionTime string) bool {
	ts := EpochMsFromAny(a["startTime"])
	tsDesc := "Process Start Time"
	if ts == "" {
		ts = collectionTime
		tsDesc = "Collection Time (Process Running)"
	}
	if ts == "" {
		return false
	}

	name := GetStr(a, "name")
	if name == "" {
		name = "unknown"
	}
	pid := GetStr(a, "pid")
	args := GetStr(a, "args")

	msg := fmt.Sprintf("Running: %s (PID:%s)", name, pid)
	if args != "" {
		display := args
		if len(display) > 100 {
			display = display[:100] + "..."
		}
		msg += " " + display
	}

	return c.AddEventFromArtifact(a, ts, tsDesc, msg, "running_process",
		"CT-Memory", "CyberTriage SystemAPI - Running Processes",
		"ct:memory:process", map[string]interface{}{
			"process_name":   name,
			"process_path":   GetStr(a, "path"),
			"raw_path_data":  GetStr(a, "rawPathData"),
			"command_line":   args,
			"pid":            pid,
			"ppid":           GetStr(a, "ppid"),
			"parent_path":    GetStr(a, "parentPath"),
			"user_id":        GetStr(a, "userID"),
			"user_domain":    GetStr(a, "userDomain"),
			"user_sid":       GetStr(a, "userSID"),
			"elevated_admin": GetStr(a, "elevatedAdminPriv"),
			"is_service":     GetStr(a, "isService"),
		})
}

func (c *Converter) ConvertDNSCache(entry Artifact, collectionTime string) bool {
	if collectionTime == "" {
		return false
	}
	hostname := GetStr(entry, "remoteHostName")
	if hostname == "" {
		return false
	}
	ip := GetStr(entry, "remoteIP")
	msg := "DNS Cache: " + hostname
	if ip != "" {
		msg += " -> " + ip
	} else {
		msg += " (no IP cached)"
	}

	return c.AddEvent(collectionTime, "Collection Time (DNS Cache Snapshot)", msg,
		"dns_cache_entry", "CT-Memory", "CyberTriage SystemAPI - DNS Cache",
		"ct:memory:dns_cache", map[string]interface{}{
			"hostname":    hostname,
			"resolved_ip": ip,
		})
}

func (c *Converter) ConvertARPCache(entry Artifact, collectionTime string) bool {
	if collectionTime == "" {
		return false
	}
	ip := GetStr(entry, "remoteIP")
	if ip == "" {
		return false
	}
	mac := GetStr(entry, "physicalAddress")
	return c.AddEvent(collectionTime, "Collection Time (ARP Cache Snapshot)",
		fmt.Sprintf("ARP Cache: %s -> %s", ip, mac),
		"arp_cache_entry", "CT-Memory", "CyberTriage SystemAPI - ARP Cache",
		"ct:memory:arp_cache", map[string]interface{}{
			"ip_address":  ip,
			"mac_address": mac,
		})
}

func (c *Converter) ConvertRoutingTable(entry Artifact, collectionTime string) bool {
	if collectionTime == "" {
		return false
	}
	dest := GetStr(entry, "remoteIP")
	if dest == "" {
		return false
	}
	nextHop := GetStr(entry, "nextHopAddress")
	msg := "Route: " + dest
	if nextHop != "" && nextHop != "0.0.0.0" {
		msg += " via " + nextHop
	} else {
		msg += " (direct)"
	}

	return c.AddEvent(collectionTime, "Collection Time (Routing Table Snapshot)", msg,
		"routing_entry", "CT-Memory", "CyberTriage SystemAPI - Routing Table",
		"ct:memory:routing_table", map[string]interface{}{
			"destination": dest,
			"next_hop":    nextHop,
		})
}

func (c *Converter) ConvertActiveConnection(entry Artifact, entryTime, collectionTime string) bool {
	ts := entryTime
	tsDesc := "Connection Time"
	if ts == "" || !strings.Contains(ts, "T") {
		ts = collectionTime
		tsDesc = "Collection Time (Connection Active)"
	}
	if ts == "" {
		return false
	}

	connType := GetStr(entry, "type")
	localIP := GetStr(entry, "localIP")
	localPort := GetStr(entry, "localPort")
	remoteIP := GetStr(entry, "remoteIP")
	remotePort := GetStr(entry, "remotePort")
	protocol := GetStr(entry, "connectionType")
	if protocol == "" {
		protocol = "TCP"
	}
	pid := GetStr(entry, "pid")

	var msg string
	switch connType {
	case "listeningPort":
		msg = fmt.Sprintf("Listening: %s %s:%s", protocol, localIP, localPort)
	case "establishedConnection":
		msg = fmt.Sprintf("Connected: %s:%s -> %s:%s", localIP, localPort, remoteIP, remotePort)
	case "udpListener":
		msg = fmt.Sprintf("UDP Listener: %s:%s", localIP, localPort)
	default:
		msg = fmt.Sprintf("Network: %s:%s -> %s:%s", localIP, localPort, remoteIP, remotePort)
	}
	if pid != "" {
		msg += fmt.Sprintf(" (PID:%s)", pid)
	}

	return c.AddEventFromArtifact(entry, ts, tsDesc, msg, "active_connection",
		"CT-Memory", "CyberTriage SystemAPI - Network Connections",
		"windows:network:connection", map[string]interface{}{
			"connection_type":  connType,
			"protocol":         protocol,
			"local_ip":         localIP,
			"local_port":       localPort,
			"remote_ip":        remoteIP,
			"remote_port":      remotePort,
			"pid":              pid,
			"state":            GetStr(entry, "state"),
			"direction":        GetStr(entry, "direction"),
			"local_host_name":  GetStr(entry, "localHostName"),
			"local_domain":     GetStr(entry, "localDomain"),
			"remote_domain":    GetStr(entry, "remoteDomain"),
			"remote_host_name": GetStr(entry, "remoteHostName"),
		})
}

// ---------------------------------------------------------------------------
// Logon Session converters (SystemAPI)
// ---------------------------------------------------------------------------

func (c *Converter) ConvertLogonSession(a Artifact) bool {
	ts := EpochMsFromAny(a["startTime"])
	tsDesc := "Logon Session Start"
	if ts == "" {
		ts = EpochMsFromAny(a["endTime"])
		tsDesc = "Logon Session End"
	}
	if ts == "" {
		return false
	}

	userID := GetStr(a, "userID")
	userDomain := GetStr(a, "userDomain")
	remoteIP := GetStr(a, "remoteIP")
	sourceIP := GetStr(a, "sourceIP")
	loginType := GetStr(a, "loginType")
	direction := GetStr(a, "direction")
	loginStatus := GetStr(a, "loginStatus")

	u := userID
	if userDomain != "" {
		u = userDomain + "\\" + userID
	}
	msg := "Logon session: " + u
	ip := remoteIP
	if ip == "" {
		ip = sourceIP
	}
	if ip != "" {
		msg += " from " + ip
	}
	if loginType != "" {
		msg += " (Type: " + loginType + ")"
	}
	if loginStatus != "" && loginStatus != "success" {
		msg += " [" + loginStatus + "]"
	}

	return c.AddEventFromArtifact(a, ts, tsDesc, msg, "logon_session",
		"CT-SystemAPI", "CyberTriage SystemAPI - Logon Sessions",
		"windows:logon:session", map[string]interface{}{
			"user_id":          userID,
			"user_domain":      userDomain,
			"user_sid":         GetStr(a, "userSID"),
			"remote_user":      GetStr(a, "remoteUser"),
			"remote_domain":    GetStr(a, "remoteDomain"),
			"remote_host_name": GetStr(a, "remoteHostName"),
			"remote_ip":        remoteIP,
			"source_ip":        sourceIP,
			"source_host_name": GetStr(a, "sourceHostName"),
			"destination_ip":   GetStr(a, "destinationIP"),
			"destination_host": GetStr(a, "destinationHostName"),
			"local_ip":         GetStr(a, "localIP"),
			"direction":        direction,
			"logon_type":       loginType,
			"logon_process":    GetStr(a, "logonProcess"),
			"login_status":     loginStatus,
			"failure_reasons":  GetStr(a, "failureReasons"),
		})
}

// ---------------------------------------------------------------------------
// Triggered Task (Scheduled Task definitions)
// ---------------------------------------------------------------------------

func (c *Converter) ConvertTriggeredTask(a Artifact) bool {
	ts := EpochMsFromAny(a["dateModified"])
	tsDesc := "Task Modified"
	if ts == "" {
		ts = EpochMsFromAny(a["dateCreated"])
		tsDesc = "Task Created"
	}
	if ts == "" {
		return false
	}

	name := GetStr(a, "name")
	if name == "" {
		name = "Unknown Task"
	}
	state := GetStr(a, "state")
	userID := GetStr(a, "userID")

	msg := "Scheduled Task: " + name
	if state != "" {
		msg += " [" + state + "]"
	}
	if userID != "" {
		msg += " (Run as: " + userID + ")"
	}

	var actionPaths []string
	if actions, ok := a["actions"].([]interface{}); ok {
		for _, act := range actions {
			if am, ok := act.(map[string]interface{}); ok {
				p := GetStr(am, "path")
				args := GetStr(am, "args")
				if p != "" {
					entry := p
					if args != "" {
						entry += " " + args
					}
					actionPaths = append(actionPaths, entry)
				}
			}
		}
	}

	var actionsStr string
	if len(actionPaths) > 0 {
		actionsStr = strings.Join(actionPaths, "; ")
	}

	return c.AddEventFromArtifact(a, ts, tsDesc, msg, "triggered_task",
		"CT-CollectionTool", "CyberTriage CollectionTool - Scheduled Tasks",
		"windows:tasks:job", map[string]interface{}{
			"task_name":   name,
			"task_state":  state,
			"description": GetStr(a, "description"),
			"triggers":    GetStr(a, "triggers"),
			"actions":     actionsStr,
			"user_id":     userID,
			"user_domain": GetStr(a, "userDomain"),
			"user_sid":    GetStr(a, "userSID"),
		})
}

// ---------------------------------------------------------------------------
// Web Artifact (CT pre-parsed browser history)
// ---------------------------------------------------------------------------

func (c *Converter) ConvertWebArtifact(a Artifact) bool {
	ts := EpochMsFromAny(a["dateAccessed"])
	tsDesc := "Web Page Accessed"
	if ts == "" {
		ts = EpochMsFromAny(a["dateCreated"])
		tsDesc = "Web Download Created"
	}
	if ts == "" {
		return false
	}

	artifactType := GetStr(a, "type")
	url := GetStr(a, "url")
	title := GetStr(a, "title")
	userID := GetStr(a, "userID")

	msg := ""
	eventType := "web_visit"
	switch artifactType {
	case "DOWNLOAD":
		eventType = "web_download"
		tsDesc = "Web Download Time"
		msg = "Download: " + url
		if title != "" {
			msg = "Download: " + title + " (" + url + ")"
		}
	default:
		msg = "Visited: " + url
		if title != "" {
			msg = "Visited: " + title + " (" + url + ")"
		}
	}
	if userID != "" {
		msg += " [" + userID + "]"
	}

	return c.AddEventFromArtifact(a, ts, tsDesc, msg, eventType,
		"CT-WebArtifact", "CyberTriage - Web Artifact",
		"ct:web:artifact", map[string]interface{}{
			"url":              url,
			"title":            title,
			"visit_type":       GetStr(a, "visitType"),
			"referrer_url":     GetStr(a, "refURL"),
			"remote_host_name": GetStr(a, "remoteHostName"),
			"visit_count":      GetStr(a, "visitCount"),
			"local_path":       GetStr(a, "path"),
			"query":            GetStr(a, "query"),
			"artifact_type":    artifactType,
			"user_id":          userID,
			"user_sid":         GetStr(a, "userSID"),
			"user_domain":      GetStr(a, "userDomain"),
		})
}

// ---------------------------------------------------------------------------
// Attached Device (USB/PCI device history)
// ---------------------------------------------------------------------------

func (c *Converter) ConvertAttachedDevice(a Artifact) int {
	added := 0
	busType := GetStr(a, "busType")
	vendorId := GetStr(a, "vendorId")
	productId := GetStr(a, "productId")
	serialNum := GetStr(a, "serialNum")

	deviceDesc := busType + " " + vendorId
	if productId != "" {
		deviceDesc += " " + productId
	}
	if serialNum != "" {
		deviceDesc += " (S/N: " + serialNum + ")"
	}

	type tsEntry struct {
		field string
		desc  string
		word  string
	}
	entries := []tsEntry{
		{"firstConnectTime", "Device First Connected", "first connected"},
		{"lastConnectTime", "Device Last Connected", "last connected"},
		{"lastDisconnectTime", "Device Last Disconnected", "last disconnected"},
	}

	for _, e := range entries {
		ts := EpochMsFromAny(a[e.field])
		if ts == "" {
			continue
		}
		msg := "Device " + e.word + ": " + deviceDesc
		if c.AddEventFromArtifact(a, ts, e.desc, msg, "attached_device",
			"CT-CollectionTool", "CyberTriage CollectionTool - Attached Devices",
			"windows:registry:usbstor", map[string]interface{}{
				"bus_type":   busType,
				"vendor_id":  vendorId,
				"product_id": productId,
				"serial_num": serialNum,
			}) {
			added++
		}
	}
	return added
}

// ---------------------------------------------------------------------------
// Log Line (parsed log file entries)
// ---------------------------------------------------------------------------

func (c *Converter) ConvertLogLine(a Artifact) bool {
	ts := EpochMsFromAny(a["time"])
	if ts == "" {
		return false
	}

	logName := GetStr(a, "logName")
	eventID := GetInt(a, "eventID")
	userID := GetStr(a, "userID")
	payload := GetMap(a, "payload")

	msg := fmt.Sprintf("Log: %s Event %d", logName, eventID)
	if userID != "" {
		msg += " (User: " + userID + ")"
	}

	attrs := map[string]interface{}{
		"log_name":    logName,
		"log_path":    GetStr(a, "logPath"),
		"event_id":    fmt.Sprintf("%d", eventID),
		"record_id":   a["recordID"],
		"user_id":     userID,
		"user_domain": GetStr(a, "userDomain"),
		"user_sid":    GetStr(a, "userSID"),
	}
	if payload != nil {
		for k, v := range payload {
			if v != nil {
				attrs[k] = fmt.Sprint(v)
			}
		}
	}

	return c.AddEventFromArtifact(a, ts, "Log Entry", msg, "log_line",
		"CT-LogLine", "CyberTriage - Parsed Log Entry",
		"ct:log:line", attrs)
}

// ---------------------------------------------------------------------------
// OS Config Setting (firewall, audit policy, PATH)
// ---------------------------------------------------------------------------

func (c *Converter) ConvertOSConfigSetting(a Artifact, collectionTime string) bool {
	ts := collectionTime
	if ts == "" {
		si := GetMap(a, "sourceInfo")
		if si != nil {
			ts = EpochMsFromAny(si["lastWriteTime"])
		}
	}
	if ts == "" {
		return false
	}

	setting := GetStr(a, "setting")
	value := GetStr(a, "value")
	group := GetStr(a, "group")

	msg := "OS Config: " + setting
	if value != "" {
		display := value
		if len(display) > 80 {
			display = display[:80] + "..."
		}
		msg += " = " + display
	}

	return c.AddEventFromArtifact(a, ts, "Collection Time (OS Configuration)", msg, "os_config",
		"CT-CollectionTool", "CyberTriage CollectionTool - OS Configuration",
		"ct:os:config_setting", map[string]interface{}{
			"setting": setting,
			"value":   value,
			"group":   group,
		})
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func copyAttrs(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{}, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func extractAppName(app string) string {
	if i := strings.LastIndex(app, "\\"); i >= 0 {
		app = app[i+1:]
	}
	if i := strings.LastIndex(app, "/"); i >= 0 {
		app = app[i+1:]
	}
	return app
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
