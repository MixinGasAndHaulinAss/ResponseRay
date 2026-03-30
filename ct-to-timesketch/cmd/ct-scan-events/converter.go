package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// TimesketchEvent is the final output format for Timesketch JSONL.
type TimesketchEvent struct {
	Datetime      string `json:"datetime"`
	TimestampDesc string `json:"timestamp_desc"`
	Message       string `json:"message"`
	DataType      string `json:"data_type"`
	EventType     string `json:"event_type"`
	SourceShort   string `json:"source_short"`
	SourceLong    string `json:"source_long"`
	HostName      string `json:"host_name"`
	// Flattened attributes are added via the extra map
}

// timesketchOutput holds the structured fields plus dynamic attributes.
type timesketchOutput struct {
	base  TimesketchEvent
	attrs map[string]string
}

func (o *timesketchOutput) marshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"datetime":       o.base.Datetime,
		"timestamp_desc": o.base.TimestampDesc,
		"message":        o.base.Message,
		"data_type":      o.base.DataType,
		"event_type":     o.base.EventType,
		"source_short":   o.base.SourceShort,
		"source_long":    o.base.SourceLong,
		"host_name":      o.base.HostName,
	}
	for k, v := range o.attrs {
		if v != "" {
			m[k] = v
		}
	}
	return json.Marshal(m)
}

var providerMappings = map[string]string{
	"Security":       "Microsoft-Windows-Security-Auditing",
	"System":         "Microsoft-Windows-Kernel-General",
	"Microsoft-Windows-PowerShell/Operational":                                   "Microsoft-Windows-PowerShell",
	"Windows PowerShell":                                                         "PowerShell",
	"PowerShell":                                                                 "Microsoft-Windows-PowerShell",
	"Microsoft-Windows-TaskScheduler/Operational":                                "Microsoft-Windows-TaskScheduler",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational":         "Microsoft-Windows-TerminalServices-LocalSessionManager",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational":     "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
	"Microsoft-Windows-Sysmon/Operational":                                       "Microsoft-Windows-Sysmon",
	"Microsoft-Windows-Windows Defender/Operational":                              "Microsoft-Windows-Windows Defender",
	"Application":                                                                "Application",
	"Microsoft-Windows-WMI-Activity/Operational":                                 "Microsoft-Windows-WMI-Activity",
	"Microsoft-Windows-Bits-Client/Operational":                                  "Microsoft-Windows-Bits-Client",
	"Microsoft-Windows-DNS-Client/Operational":                                   "Microsoft-Windows-DNS-Client",
	"DNS Server":                                                                 "Microsoft-Windows-DNS-Server-Service",
	"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall":         "Microsoft-Windows-Windows Firewall With Advanced Security",
}

var eventIDChannelMap = map[int]string{
	// Security Log
	4624: "Security", 4625: "Security", 4634: "Security", 4647: "Security",
	4648: "Security", 4672: "Security", 4768: "Security", 4769: "Security",
	4770: "Security", 4771: "Security", 4776: "Security",
	4720: "Security", 4722: "Security", 4723: "Security", 4724: "Security",
	4725: "Security", 4726: "Security", 4728: "Security", 4729: "Security",
	4732: "Security", 4733: "Security", 4740: "Security", 4756: "Security",
	4757: "Security",
	4688: "Security", 4689: "Security",
	4656: "Security", 4658: "Security", 4660: "Security", 4663: "Security",
	4704: "Security", 4705: "Security", 4719: "Security",
	1102: "Security", 4616: "Security",
	5152: "Security", 5153: "Security", 5154: "Security", 5155: "Security",
	5156: "Security", 5157: "Security", 5158: "Security", 5159: "Security",
	4703: "Security", 4673: "Security", 4674: "Security",
	4662: "Security", 5136: "Security", 5137: "Security", 5138: "Security",
	5139: "Security", 5141: "Security",
	4773: "Security", 4774: "Security", 4775: "Security",
	6416: "Security",
	// System
	7045: "System", 7036: "System", 7040: "System", 7034: "System",
	7026: "System", 104: "System", 1074: "System",
	6005: "System", 6006: "System", 6008: "System", 6009: "System", 6013: "System",
	// Sysmon
	1: "Microsoft-Windows-Sysmon/Operational", 2: "Microsoft-Windows-Sysmon/Operational",
	3: "Microsoft-Windows-Sysmon/Operational", 5: "Microsoft-Windows-Sysmon/Operational",
	6: "Microsoft-Windows-Sysmon/Operational", 7: "Microsoft-Windows-Sysmon/Operational",
	8: "Microsoft-Windows-Sysmon/Operational", 9: "Microsoft-Windows-Sysmon/Operational",
	10: "Microsoft-Windows-Sysmon/Operational", 11: "Microsoft-Windows-Sysmon/Operational",
	12: "Microsoft-Windows-Sysmon/Operational", 13: "Microsoft-Windows-Sysmon/Operational",
	14: "Microsoft-Windows-Sysmon/Operational", 15: "Microsoft-Windows-Sysmon/Operational",
	17: "Microsoft-Windows-Sysmon/Operational", 18: "Microsoft-Windows-Sysmon/Operational",
	19: "Microsoft-Windows-Sysmon/Operational", 20: "Microsoft-Windows-Sysmon/Operational",
	26: "Microsoft-Windows-Sysmon/Operational",
	// Note: Sysmon IDs 22-25 omitted -- overlap with Terminal Services; CT SystemAPI uses TS channel
	// PowerShell
	400: "Windows PowerShell", 403: "Windows PowerShell",
	500: "Windows PowerShell", 501: "Windows PowerShell",
	600: "Windows PowerShell", 800: "Windows PowerShell",
	4100: "Microsoft-Windows-PowerShell/Operational",
	4103: "Microsoft-Windows-PowerShell/Operational",
	4104: "Microsoft-Windows-PowerShell/Operational",
	4105: "Microsoft-Windows-PowerShell/Operational",
	4106: "Microsoft-Windows-PowerShell/Operational",
	40961: "Microsoft-Windows-PowerShell/Operational",
	40962: "Microsoft-Windows-PowerShell/Operational",
	410: "Microsoft-Windows-PowerShell/Operational",
	411: "Microsoft-Windows-PowerShell/Operational",
	420: "Microsoft-Windows-PowerShell/Operational",
	// Task Scheduler
	100: "Microsoft-Windows-TaskScheduler/Operational",
	102: "Microsoft-Windows-TaskScheduler/Operational",
	106: "Microsoft-Windows-TaskScheduler/Operational",
	107: "Microsoft-Windows-TaskScheduler/Operational",
	110: "Microsoft-Windows-TaskScheduler/Operational",
	118: "Microsoft-Windows-TaskScheduler/Operational",
	119: "Microsoft-Windows-TaskScheduler/Operational",
	129: "Microsoft-Windows-TaskScheduler/Operational",
	140: "Microsoft-Windows-TaskScheduler/Operational",
	141: "Microsoft-Windows-TaskScheduler/Operational",
	142: "Microsoft-Windows-TaskScheduler/Operational",
	200: "Microsoft-Windows-TaskScheduler/Operational",
	201: "Microsoft-Windows-TaskScheduler/Operational",
	// Terminal Services / RDP (wins over Sysmon for IDs 21-25 in CT SystemAPI context)
	21: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	22: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	23: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	24: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	25: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	// Defender
	1000: "Microsoft-Windows-Windows Defender/Operational",
	1001: "Microsoft-Windows-Windows Defender/Operational",
	1002: "Microsoft-Windows-Windows Defender/Operational",
	1005: "Microsoft-Windows-Windows Defender/Operational",
	1006: "Microsoft-Windows-Windows Defender/Operational",
	1007: "Microsoft-Windows-Windows Defender/Operational",
	1008: "Microsoft-Windows-Windows Defender/Operational",
	1116: "Microsoft-Windows-Windows Defender/Operational",
	1117: "Microsoft-Windows-Windows Defender/Operational",
	2000: "Microsoft-Windows-Windows Defender/Operational",
	2001: "Microsoft-Windows-Windows Defender/Operational",
	5001: "Microsoft-Windows-Windows Defender/Operational",
	5004: "Microsoft-Windows-Windows Defender/Operational",
	5007: "Microsoft-Windows-Windows Defender/Operational",
	// WMI
	5857: "Microsoft-Windows-WMI-Activity/Operational",
	5858: "Microsoft-Windows-WMI-Activity/Operational",
	5859: "Microsoft-Windows-WMI-Activity/Operational",
	5860: "Microsoft-Windows-WMI-Activity/Operational",
	5861: "Microsoft-Windows-WMI-Activity/Operational",
	// AppLocker
	8002: "Microsoft-Windows-AppLocker/EXE and DLL",
	8003: "Microsoft-Windows-AppLocker/EXE and DLL",
	8004: "Microsoft-Windows-AppLocker/EXE and DLL",
	// Firewall
	2003: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
	2004: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
	2005: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
	2006: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
}

func epochMsToISO(ms int64) string {
	sec := ms / 1000
	nsec := (ms % 1000) * 1_000_000
	t := time.Unix(sec, nsec).UTC()
	return t.Format("2006-01-02T15:04:05.000") + "Z"
}

func getProviderName(logName string) string {
	if logName == "" || logName == "Unknown" {
		return "Unknown"
	}
	if p, ok := providerMappings[logName]; ok {
		return p
	}
	lower := strings.ToLower(logName)
	for key, provider := range providerMappings {
		if strings.Contains(lower, strings.ToLower(key)) {
			return provider
		}
	}
	if strings.Contains(logName, "Microsoft-Windows-") {
		return strings.SplitN(logName, "/", 2)[0]
	}
	return logName
}

func inferChannel(eid int) (string, string) {
	if ch, ok := eventIDChannelMap[eid]; ok {
		return ch, getProviderName(ch)
	}
	return "", ""
}

func buildMessage(eid int, logName string, payload map[string]interface{}) string {
	get := func(key string) string {
		if v, ok := payload[key]; ok {
			return fmt.Sprint(v)
		}
		return ""
	}

	if strings.Contains(logName, "Security") {
		switch eid {
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

	return fmt.Sprintf("Windows Event %d from %s", eid, logName)
}

func categorizeEvent(eid int, logName string) string {
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
	if strings.Contains(logName, "System") {
		if eid == 7045 || eid == 7040 || eid == 7036 {
			return "windows_service"
		}
	}
	return "windows_event"
}

// convertWindowsEvent takes a raw windowsEvent JSON object and returns
// a Timesketch JSONL line, or nil if the event should be skipped.
func convertWindowsEvent(raw json.RawMessage, hostname string) ([]byte, error) {
	var we map[string]interface{}
	if err := json.Unmarshal(raw, &we); err != nil {
		return nil, err
	}

	timeVal, ok := we["time"]
	if !ok {
		return nil, fmt.Errorf("no time field")
	}
	var timeMs int64
	switch t := timeVal.(type) {
	case float64:
		timeMs = int64(t)
	case json.Number:
		v, err := t.Int64()
		if err != nil {
			return nil, err
		}
		timeMs = v
	default:
		return nil, fmt.Errorf("unexpected time type")
	}
	if timeMs == 0 {
		return nil, fmt.Errorf("zero time")
	}
	dt := epochMsToISO(timeMs)

	eventIDVal, _ := we["eventID"]
	eid := 0
	switch v := eventIDVal.(type) {
	case float64:
		eid = int(v)
	case json.Number:
		n, _ := v.Int64()
		eid = int(n)
	}

	sourceInfo, _ := we["sourceInfo"].(map[string]interface{})
	eventLogName := "Unknown"
	if sourceInfo != nil {
		if n, ok := sourceInfo["eventLogName"].(string); ok && n != "" {
			eventLogName = n
		}
	}

	recordID := ""
	if rid, ok := we["recordID"]; ok && rid != nil {
		recordID = fmt.Sprint(rid)
	}
	if recordID == "" && sourceInfo != nil {
		if rid, ok := sourceInfo["eventLogRecordId"]; ok && rid != nil {
			recordID = fmt.Sprint(rid)
		}
	}

	payload := make(map[string]interface{})
	if p, ok := we["payload"].(map[string]interface{}); ok {
		payload = p
	}

	sourceName := ""
	if eventLogName == "Unknown" || eventLogName == "" {
		ch, sn := inferChannel(eid)
		if ch != "" {
			eventLogName = ch
			sourceName = sn
		} else {
			sourceName = "Unknown"
		}
	} else {
		sourceName = getProviderName(eventLogName)
	}

	message := buildMessage(eid, eventLogName, payload)
	eventType := categorizeEvent(eid, eventLogName)

	// Build flattened output map
	out := map[string]interface{}{
		"datetime":         dt,
		"timestamp_desc":   "Windows Event Log Entry",
		"message":          message,
		"data_type":        "windows:evtx:record",
		"event_type":       eventType,
		"source_short":     "CT-EventLog",
		"source_long":      "CyberTriage SystemAPI - " + eventLogName,
		"host_name":        hostname,
		"source_name":      sourceName,
		"channel":          eventLogName,
		"event_identifier": strconv.Itoa(eid),
		"computer_name":    hostname,
	}
	if recordID != "" {
		out["record_number"] = recordID
	}

	for k, v := range payload {
		if v != nil {
			s := fmt.Sprint(v)
			if s != "" {
				out[k] = s
			}
		}
	}

	return json.Marshal(out)
}
