package converter

import (
	"fmt"
	"strconv"
	"strings"
)

// ConvertWindowsEvent converts a CyberTriage pre-parsed windowsEvent artifact.
func (c *Converter) ConvertWindowsEvent(a Artifact) bool {
	ts := EpochMsFromAny(a["time"])
	if ts == "" {
		return false
	}

	eid := GetInt(a, "eventID")
	sourceInfo := GetMap(a, "sourceInfo")
	eventLogName := "Unknown"
	if sourceInfo != nil {
		if n := GetStr(sourceInfo, "eventLogName"); n != "" {
			eventLogName = n
		}
	}

	recordID := GetStr(a, "recordID")
	if recordID == "" && sourceInfo != nil {
		recordID = GetStr(sourceInfo, "eventLogRecordId")
	}

	payload := GetMap(a, "payload")
	if payload == nil {
		payload = make(map[string]interface{})
	}

	sourceName := ""
	if eventLogName == "Unknown" || eventLogName == "" {
		ch, sn := InferChannel(eid)
		if ch != "" {
			eventLogName = ch
			sourceName = sn
		} else {
			sourceName = "Unknown"
		}
	} else {
		sourceName = GetProviderName(eventLogName)
	}

	message := BuildWindowsEventMessage(eid, eventLogName, payload)
	eventType := CategorizeWindowsEvent(eid, eventLogName)

	attrs := map[string]interface{}{
		"source_name":      sourceName,
		"channel":          eventLogName,
		"event_identifier": strconv.Itoa(eid),
		"computer_name":    c.Hostname,
	}
	if recordID != "" {
		attrs["record_number"] = recordID
	}
	for k, v := range payload {
		if v != nil {
			attrs[k] = fmt.Sprint(v)
		}
	}

	return c.AddEvent(
		ts,
		"Windows Event Log Entry",
		message,
		eventType,
		"CT-EventLog",
		"CyberTriage SystemAPI - "+eventLogName,
		"windows:evtx:record",
		attrs,
	)
}

// BuildWindowsEventMessage builds a human-readable message for common event types.
func BuildWindowsEventMessage(eid int, logName string, payload map[string]interface{}) string {
	get := func(key string) string { return GetStr(payload, key) }

	if strings.Contains(logName, "Security") {
		switch eid {
		case 4624:
			user := get("TargetUserName")
			if user == "" {
				user = "Unknown"
			}
			lt := get("LogonType")
			if lt == "" {
				lt = "?"
			}
			return fmt.Sprintf("Logon: %s (Type %s)", user, lt)
		case 4625:
			user := get("TargetUserName")
			if user == "" {
				user = "Unknown"
			}
			return "Failed logon: " + user
		case 4634:
			user := get("TargetUserName")
			if user == "" {
				user = "Unknown"
			}
			return "Logoff: " + user
		case 4648:
			user := get("SubjectUserName")
			if user == "" {
				user = "Unknown"
			}
			target := get("TargetServerName")
			if target == "" {
				target = "Unknown"
			}
			return fmt.Sprintf("Explicit credentials: %s → %s", user, target)
		case 4672:
			user := get("SubjectUserName")
			if user == "" {
				user = "Unknown"
			}
			return "Special privileges assigned: " + user
		case 4688:
			proc := get("NewProcessName")
			if proc == "" {
				proc = "Unknown"
			}
			user := get("SubjectUserName")
			if user == "" {
				user = "Unknown"
			}
			return fmt.Sprintf("Process created: %s by %s", proc, user)
		case 4689:
			proc := get("ProcessName")
			if proc == "" {
				proc = "Unknown"
			}
			return "Process exited: " + proc
		case 4720:
			return "User account created: " + get("TargetUserName")
		case 4726:
			return "User account deleted: " + get("TargetUserName")
		case 4732:
			return fmt.Sprintf("User %s added to group %s", get("MemberName"), get("TargetUserName"))
		case 4776:
			user := get("TargetUserName")
			if user == "" {
				user = "Unknown"
			}
			return "Credential validation: " + user
		case 5156, 5157:
			app := get("Application")
			if app == "" {
				app = "Unknown"
			}
			action := "allowed"
			if eid == 5157 {
				action = "blocked"
			}
			return fmt.Sprintf("WFP %s: %s %s:%s → %s:%s",
				action, app, get("SourceAddress"), get("SourcePort"),
				get("DestAddress"), get("DestPort"))
		case 5152:
			app := get("Application")
			if app == "" {
				app = "Unknown"
			}
			return fmt.Sprintf("WFP dropped packet: %s %s → %s",
				app, get("SourceAddress"), get("DestAddress"))
		}
	}

	if strings.Contains(logName, "PowerShell") {
		switch eid {
		case 4104:
			script := get("ScriptBlockText")
			if len(script) > 100 {
				script = script[:100]
			}
			return "PowerShell script: " + script + "..."
		case 400:
			return "PowerShell engine started"
		case 403:
			return "PowerShell engine stopped"
		}
	}

	if strings.Contains(logName, "Dhcp") || strings.Contains(logName, "DHCP") {
		ipAddr := get("IPAddress")
		if ipAddr == "" {
			ipAddr = get("ipAddress")
		}
		hostname := get("HostName")
		if hostname == "" {
			hostname = get("hostname")
		}
		switch eid {
		case 10:
			if hostname != "" {
				return fmt.Sprintf("DHCP: Lease assigned %s to %s", ipAddr, hostname)
			}
			return "DHCP: Lease assigned " + ipAddr
		case 11:
			return "DHCP: Lease renewed " + ipAddr
		case 12:
			return "DHCP: Lease released " + ipAddr
		case 15:
			return "DHCP: Lease expired " + ipAddr
		}
		return fmt.Sprintf("DHCP: Event %d", eid)
	}

	if strings.Contains(logName, "Task") {
		taskName := get("TaskName")
		if taskName == "" {
			taskName = get("Name")
		}
		if taskName == "" {
			taskName = "Unknown"
		}
		switch eid {
		case 106:
			return "Scheduled task registered: " + taskName
		case 200:
			return "Scheduled task started: " + taskName
		case 201:
			return "Scheduled task completed: " + taskName
		case 141:
			return "Scheduled task deleted: " + taskName
		}
		return fmt.Sprintf("Task Scheduler event %d: %s", eid, taskName)
	}

	if strings.Contains(logName, "TerminalServices") {
		user := get("User")
		if user == "" {
			user = get("UserName")
		}
		address := get("Address")
		if address == "" {
			address = get("Param3")
		}
		userInfo := user
		if address != "" && address != "LOCAL" {
			userInfo = user + " from " + address
		} else if address == "LOCAL" {
			userInfo = user + " (local console)"
		}
		switch eid {
		case 21:
			return "RDP session logon: " + userInfo
		case 22:
			return "RDP shell start: " + userInfo
		case 23:
			return "RDP session logoff: " + userInfo
		case 24:
			return "RDP session disconnected: " + userInfo
		case 25:
			return "RDP session reconnected: " + userInfo
		case 40:
			sessID := get("SessionID")
			if sessID == "" {
				sessID = get("Session")
			}
			return fmt.Sprintf("RDP session %s disconnected (reason code in event)", sessID)
		case 1149:
			return "RDP authentication succeeded: " + userInfo
		}
		return fmt.Sprintf("Terminal Services event %d", eid)
	}

	// TS-Gateway events
	if strings.Contains(logName, "TerminalServices-Gateway") {
		user := get("Param1")
		clientIP := get("Param2")
		resource := get("Param3")
		if user != "" || clientIP != "" {
			switch eid {
			case 302:
				return fmt.Sprintf("TS-Gateway connected: %s from %s to %s", user, clientIP, resource)
			case 303:
				return fmt.Sprintf("TS-Gateway disconnected: %s from %s", user, clientIP)
			case 312:
				return fmt.Sprintf("TS-Gateway auth failed: %s from %s", user, clientIP)
			case 300:
				return fmt.Sprintf("TS-Gateway policy: %s from %s", user, clientIP)
			}
		}
		return fmt.Sprintf("TS-Gateway event %d", eid)
	}

	if strings.Contains(logName, "System") {
		switch eid {
		case 7045:
			return "Service installed: " + get("ServiceName")
		case 7040:
			return "Service start type changed: " + get("param1")
		}
	}

	return fmt.Sprintf("Windows Event %d from %s", eid, logName)
}

// CategorizeWindowsEvent returns a Timesketch event_type based on event ID and channel.
func CategorizeWindowsEvent(eid int, logName string) string {
	if strings.Contains(logName, "Security") {
		switch eid {
		case 4624, 4625, 4634, 4647, 4648, 4672:
			return "windows_logon"
		case 4688, 4689:
			return "windows_process"
		case 4720, 4722, 4723, 4724, 4725, 4726, 4732, 4733:
			return "windows_account"
		case 4776, 4768, 4769, 4771:
			return "windows_authentication"
		case 5156, 5157, 5152, 5153, 5154, 5155, 5158, 5159:
			return "windows_firewall"
		}
	}
	if strings.Contains(logName, "Task") {
		return "windows_task"
	}
	if strings.Contains(logName, "TerminalServices") {
		return "windows_rdp"
	}
	if strings.Contains(logName, "PowerShell") {
		return "windows_powershell"
	}
	if strings.Contains(logName, "DNS") {
		return "windows_dns"
	}
	if strings.Contains(logName, "SmbClient") || strings.Contains(logName, "SMB") {
		return "windows_smb"
	}
	if strings.Contains(logName, "Defender") {
		return "windows_defender"
	}
	if strings.Contains(logName, "Dhcp") || strings.Contains(logName, "DHCP") {
		return "windows_dhcp"
	}
	if strings.Contains(logName, "System") {
		if eid == 7045 || eid == 7040 || eid == 7036 {
			return "windows_service"
		}
	}
	return "windows_event"
}
