package linux

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/responseray/responseray/internal/collectoringest/core"
)

// processLinuxSecurity parses security-related artifacts (SUID, shared memory, etc.).
func processLinuxSecurity(em *core.Emitter, dirPath, ts string) int {
	liveDir := filepath.Join(dirPath, "live")
	total := 0
	total += parseSUIDBinaries(em, filepath.Join(liveDir, "suid_binaries.txt"), ts)
	total += parseSGIDBinaries(em, filepath.Join(liveDir, "sgid_binaries.txt"), ts)
	total += parseSharedMemory(em, filepath.Join(liveDir, "shm_segments.txt"), ts)
	total += parseUlimit(em, filepath.Join(liveDir, "ulimit.txt"), ts)
	total += parseEnvironment(em, filepath.Join(liveDir, "environment.txt"), ts)
	return total
}

var reLsLa = regexp.MustCompile(`^(-[rwxsStT-]+)\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+\S+\s+\d+\s+[\d:]+\s+(.+)$`)

func parseSUIDBinaries(em *core.Emitter, path, ts string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	added := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse ls -la output
		matches := reLsLa.FindStringSubmatch(line)
		if len(matches) < 6 {
			// Fallback: just extract the path
			fields := strings.Fields(line)
			if len(fields) > 0 {
				binPath := fields[len(fields)-1]
				msg := fmt.Sprintf("SUID binary: %s", binPath)
				if em.AddEvent(ts, "SUID Binary Found", msg, "suid_binary",
					"RR-Linux", "ResponseRay Linux Collector - Security",
					"linux:security:suid", map[string]interface{}{
						"path": binPath,
						"raw":  line,
					}) {
					added++
				}
			}
			continue
		}

		perms := matches[1]
		owner := matches[2]
		group := matches[3]
		size := matches[4]
		binPath := matches[5]

		msg := fmt.Sprintf("SUID binary: %s (owner=%s, perms=%s)", binPath, owner, perms)
		if em.AddEvent(ts, "SUID Binary Found", msg, "suid_binary",
			"RR-Linux", "ResponseRay Linux Collector - Security",
			"linux:security:suid", map[string]interface{}{
				"path":        binPath,
				"permissions": perms,
				"owner":       owner,
				"group":       group,
				"size":        size,
			}) {
			added++
		}
	}
	return added
}

func parseSGIDBinaries(em *core.Emitter, path, ts string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	added := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		matches := reLsLa.FindStringSubmatch(line)
		if len(matches) < 6 {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				binPath := fields[len(fields)-1]
				msg := fmt.Sprintf("SGID binary: %s", binPath)
				if em.AddEvent(ts, "SGID Binary Found", msg, "sgid_binary",
					"RR-Linux", "ResponseRay Linux Collector - Security",
					"linux:security:sgid", map[string]interface{}{
						"path": binPath,
						"raw":  line,
					}) {
					added++
				}
			}
			continue
		}

		perms := matches[1]
		owner := matches[2]
		group := matches[3]
		size := matches[4]
		binPath := matches[5]

		msg := fmt.Sprintf("SGID binary: %s (group=%s, perms=%s)", binPath, group, perms)
		if em.AddEvent(ts, "SGID Binary Found", msg, "sgid_binary",
			"RR-Linux", "ResponseRay Linux Collector - Security",
			"linux:security:sgid", map[string]interface{}{
				"path":        binPath,
				"permissions": perms,
				"owner":       owner,
				"group":       group,
				"size":        size,
			}) {
			added++
		}
	}
	return added
}

func parseSharedMemory(em *core.Emitter, path, ts string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	added := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	inHeader := true
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if inHeader {
			if strings.HasPrefix(line, "------") || strings.HasPrefix(line, "key") || strings.HasPrefix(line, "shmid") {
				continue
			}
			if strings.Contains(line, "Shared Memory Segments") {
				continue
			}
			inHeader = false
		}

		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		// Format: key shmid owner perms bytes nattch status
		key := fields[0]
		shmid := fields[1]
		owner := fields[2]
		perms := fields[3]
		bytes := fields[4]
		nattch := fields[5]

		msg := fmt.Sprintf("Shared memory: %s (owner=%s, %s bytes, %s attached)", shmid, owner, bytes, nattch)
		if em.AddEvent(ts, "Shared Memory Segment", msg, "shared_memory",
			"RR-Linux", "ResponseRay Linux Collector - Security",
			"linux:memory:shm", map[string]interface{}{
				"key":         key,
				"shmid":       shmid,
				"owner":       owner,
				"permissions": perms,
				"bytes":       bytes,
				"nattach":     nattch,
			}) {
			added++
		}
	}
	return added
}

func parseUlimit(em *core.Emitter, path, ts string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	body := strings.TrimSpace(string(data))
	if body == "" {
		return 0
	}

	// Emit one summary event
	preview := body
	if len(preview) > 200 {
		preview = preview[:200] + "..."
	}
	msg := fmt.Sprintf("Resource limits (ulimit): %s", strings.ReplaceAll(preview, "\n", "; "))
	if em.AddEvent(ts, "Resource Limits", msg, "os_config",
		"RR-Linux", "ResponseRay Linux Collector - ulimit",
		"linux:os:ulimit", map[string]interface{}{
			"setting": "ulimit",
			"group":   "Resource Limits",
			"detail":  body,
		}) {
		return 1
	}
	return 0
}

func parseEnvironment(em *core.Emitter, path, ts string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	added := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		varName := line[:idx]
		varValue := line[idx+1:]

		// Skip sensitive-looking values
		lowerName := strings.ToLower(varName)
		if strings.Contains(lowerName, "password") || strings.Contains(lowerName, "secret") ||
			strings.Contains(lowerName, "token") || strings.Contains(lowerName, "key") {
			varValue = "[REDACTED]"
		}

		// Truncate long values
		if len(varValue) > 200 {
			varValue = varValue[:200] + "..."
		}

		msg := fmt.Sprintf("Environment: %s=%s", varName, varValue)
		if em.AddEvent(ts, "Environment Variable", msg, "os_config",
			"RR-Linux", "ResponseRay Linux Collector - env",
			"linux:os:env_var", map[string]interface{}{
				"setting":   varName,
				"value":     varValue,
				"group":     "Environment",
				"var_name":  varName,
				"var_value": varValue,
			}) {
			added++
		}
	}
	return added
}

// processLinuxMAC parses SELinux and AppArmor settings.
func processLinuxMAC(em *core.Emitter, dirPath, ts string) int {
	liveDir := filepath.Join(dirPath, "live")
	total := 0

	// SELinux status
	for _, file := range []string{"mac_sestatus.txt", "mac_getenforce.txt"} {
		path := filepath.Join(liveDir, file)
		if data, err := os.ReadFile(path); err == nil {
			body := strings.TrimSpace(string(data))
			if body == "" {
				continue
			}
			preview := strings.ReplaceAll(body, "\n", "; ")
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			msg := fmt.Sprintf("SELinux: %s", preview)
			if em.AddEvent(ts, "SELinux Status", msg, "os_config",
				"RR-Linux", "ResponseRay Linux Collector - SELinux",
				"linux:os:selinux", map[string]interface{}{
					"setting": "selinux",
					"group":   "Security",
					"detail":  body,
				}) {
				total++
			}
		}
	}

	// AppArmor status
	for _, file := range []string{"mac_aa-status.txt", "mac_apparmor_status.txt"} {
		path := filepath.Join(liveDir, file)
		if data, err := os.ReadFile(path); err == nil {
			body := strings.TrimSpace(string(data))
			if body == "" {
				continue
			}
			preview := strings.ReplaceAll(body, "\n", "; ")
			if len(preview) > 200 {
				preview = preview[:200] + "..."
			}
			msg := fmt.Sprintf("AppArmor: %s", preview)
			if em.AddEvent(ts, "AppArmor Status", msg, "os_config",
				"RR-Linux", "ResponseRay Linux Collector - AppArmor",
				"linux:os:apparmor", map[string]interface{}{
					"setting": "apparmor",
					"group":   "Security",
					"detail":  body,
				}) {
				total++
			}
		}
	}

	return total
}
