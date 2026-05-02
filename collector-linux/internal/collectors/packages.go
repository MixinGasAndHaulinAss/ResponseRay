package collectors

import (
	"strings"
	"time"

	"github.com/responseray/collector-linux/internal/fsutil"
)

// PackageCollector enumerates installed packages from dpkg, rpm, pacman, apk, and snap/flatpak.
type PackageCollector struct{}

func (c *PackageCollector) Name() string { return "Packages" }
func (c *PackageCollector) Description() string {
	return "Installed package inventory (dpkg/rpm/pacman/apk/snap/flatpak)"
}

func (c *PackageCollector) Collect(ctx *fsutil.Context) Result {
	start := time.Now()
	r := Result{Name: c.Name()}
	timestamp := time.Now().UTC().Format(time.RFC3339)

	output := map[string]any{"collection_timestamp": timestamp, "managers": []map[string]any{}}
	managers := []map[string]any{}

	for _, mgr := range []struct {
		name string
		args []string
	}{
		{"dpkg", []string{"dpkg-query", "-W", "-f=${Package}\\t${Version}\\t${Architecture}\\t${Status}\\n"}},
		{"rpm", []string{"rpm", "-qa", "--queryformat", "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{INSTALLTIME:date}\\t%{VENDOR}\\n"}},
		{"pacman", []string{"pacman", "-Q"}},
		{"apk", []string{"apk", "info", "-vv"}},
		{"snap", []string{"snap", "list"}},
		{"flatpak", []string{"flatpak", "list", "--columns=application,version,branch,arch,origin,installation"}},
	} {
		out, err := runCmd(mgr.args...)
		entry := map[string]any{"manager": mgr.name, "raw": out}
		if err != nil {
			entry["error"] = err.Error()
		}
		entry["count"] = strings.Count(out, "\n")
		managers = append(managers, entry)
	}

	output["managers"] = managers
	if size, err := ctx.WriteJSON("live/packages.json", "packages", output); err == nil {
		r.FilesCollected++
		r.BytesCollected += size
	}

	r.Elapsed = time.Since(start)
	return r
}
