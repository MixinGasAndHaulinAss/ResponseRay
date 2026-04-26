// Package collectors contains the macOS forensic collectors orchestrated by main.
package collectors

import "github.com/responseray/collector-macos/internal/fsutil"

type Collector interface {
	Name() string
	Run(ctx *fsutil.Context) error
}

var All = []Collector{
	&SystemInfoCollector{},
	&UserCollector{},
	&UnifiedLogCollector{},
	&LegacyLogCollector{},
	&ASLLogCollector{},
	&ShellHistoryCollector{},
	&SSHCollector{},
	&LaunchCollector{},
	&LoginItemsCollector{},
	&PersistenceCollector{},
	&NetworkCollector{},
	&FirewallCollector{},
	&ProcessCollector{},
	&KernelCollector{},
	&MountCollector{},
	&ApplicationsCollector{},
	&BrowserCollector{},
	&MailCollector{},
	&MessagesCollector{},
	&QuarantineCollector{},
	&KnowledgeCCollector{},
	&TCCCollector{},
	&CrashReportCollector{},
	&InstallHistoryCollector{},
	&TimeMachineCollector{},
	&WirelessCollector{},
	&RecentItemsCollector{},
	&SpotlightCollector{},
	&FSEventsCollector{},
	&AuditdCollector{},
	&FileSystemCollector{},
	&MemoryCollector{},
}
