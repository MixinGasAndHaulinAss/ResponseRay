package converter

import "strings"

// ProviderMappings maps log names/channels to Windows Event provider names for Sigma compatibility.
var ProviderMappings = map[string]string{
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

// EventIDChannelMap maps well-known Windows Event IDs to their log channel.
var EventIDChannelMap = map[int]string{
	// Security
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
	// PowerShell classic
	400: "Windows PowerShell", 403: "Windows PowerShell",
	500: "Windows PowerShell", 501: "Windows PowerShell",
	600: "Windows PowerShell", 800: "Windows PowerShell",
	// PowerShell Operational
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
	1149: "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
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

// InferChannel returns (channel, provider) for a known event ID.
func InferChannel(eid int) (string, string) {
	if ch, ok := EventIDChannelMap[eid]; ok {
		return ch, GetProviderName(ch)
	}
	return "", ""
}

// GetProviderName maps a log channel name to the Windows Event provider name.
func GetProviderName(logName string) string {
	if logName == "" || logName == "Unknown" {
		return "Unknown"
	}
	if p, ok := ProviderMappings[logName]; ok {
		return p
	}
	lower := strings.ToLower(logName)
	for key, provider := range ProviderMappings {
		if strings.Contains(lower, strings.ToLower(key)) {
			return provider
		}
	}
	if strings.Contains(logName, "Microsoft-Windows-") {
		return strings.SplitN(logName, "/", 2)[0]
	}
	return logName
}
