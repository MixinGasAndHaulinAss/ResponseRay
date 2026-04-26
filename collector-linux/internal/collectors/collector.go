// Package collectors holds the per-artifact collection units invoked by the main entry point.
package collectors

import (
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

// Collector is implemented by every artifact-collection unit.
type Collector interface {
	Name() string
	Description() string
	Collect(ctx *fsutil.Context) Result
}

// Result is the per-collector summary that ends up in the manifest.
type Result struct {
	Name           string
	FilesCollected int
	BytesCollected int64
	Elapsed        time.Duration
	Error          string
}

// All is the canonical ordering of collectors.
var All = []Collector{
	&SystemInfoCollector{},
	&PackageCollector{},
	&AuthLogCollector{},
	&SystemLogCollector{},
	&ShellHistoryCollector{},
	&SSHCollector{},
	&CronCollector{},
	&SystemdCollector{},
	&NetworkLiveCollector{},
	&FirewallCollector{},
	&ProcessCollector{},
	&KernelCollector{},
	&UserCollector{},
	&LogonCollector{},
	&DiskCollector{},
	&MountCollector{},
	&MACCollector{},
	&PersistenceCollector{},
	&BrowserCollector{},
	&ApplicationLogsCollector{},
	&DockerCollector{},
	&AuditdCollector{},
	&FileSystemCollector{},
	&MemoryCollector{},
}
