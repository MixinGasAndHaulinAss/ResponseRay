package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
)

// CollectorHandler serves downloads of the four ResponseRay collectors
// (Windows, Linux, macOS, ESXi). Binaries are read from CollectorsDir.
type CollectorHandler struct {
	CollectorsDir string
}

// collectorSpec describes one platform's payload on disk.
type collectorSpec struct {
	Platform     string // stable id used in URLs ("windows" | "linux" | "macos" | "esxi")
	DisplayName  string // shown to the user
	Filename     string // file under CollectorsDir/<platform>/
	ContentType  string
	Description  string
	Architecture string // "x64", "amd64+arm64 (universal)", "POSIX sh", etc.
}

var collectorCatalog = []collectorSpec{
	{
		Platform:     "windows",
		DisplayName:  "Windows Collector",
		Filename:     "ResponseRayCollector.exe",
		ContentType:  "application/vnd.microsoft.portable-executable",
		Description:  "Self-contained .NET 8 binary. VSS-aware live triage covering 300+ Windows artifacts (registry, EVTX, prefetch, USN, MFT, browsers, etc.).",
		Architecture: "x64",
	},
	{
		Platform:     "linux",
		DisplayName:  "Linux Collector",
		Filename:     "responseray-collector-linux.tar.gz",
		ContentType:  "application/gzip",
		Description:  "Static Go binary in a tar.gz with INSTALL.txt. journald, packages, persistence, Docker/Podman, auditd, file timeline.",
		Architecture: "amd64",
	},
	{
		Platform:     "macos",
		DisplayName:  "macOS Collector",
		Filename:     "responseray-collector-macos.tar.gz",
		ContentType:  "application/gzip",
		Description:  "Static Go binary in a tar.gz with INSTALL.txt. Unified logs, launchd/btm, TCC, KnowledgeC, FSEvents, browsers.",
		Architecture: "amd64",
	},
	{
		Platform:     "esxi",
		DisplayName:  "ESXi Collector",
		Filename:     "responseray-collector-esxi.sh",
		ContentType:  "application/x-sh",
		Description:  "POSIX shell script using esxcli/vim-cmd/vmkfstools. Captures host config + VM metadata.",
		Architecture: "POSIX sh",
	},
}

type collectorInfo struct {
	Platform     string `json:"platform"`
	DisplayName  string `json:"display_name"`
	Filename     string `json:"filename"`
	Description  string `json:"description"`
	Architecture string `json:"architecture"`
	Available    bool   `json:"available"`
	Size         int64  `json:"size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	ModifiedAt   string `json:"modified_at,omitempty"`
	Error        string `json:"error,omitempty"`
}

// List returns the catalog of collectors with availability + integrity metadata.
func (h *CollectorHandler) List(w http.ResponseWriter, r *http.Request) {
	out := make([]collectorInfo, 0, len(collectorCatalog))
	for _, spec := range collectorCatalog {
		info := collectorInfo{
			Platform:     spec.Platform,
			DisplayName:  spec.DisplayName,
			Filename:     spec.Filename,
			Description:  spec.Description,
			Architecture: spec.Architecture,
		}
		path := h.diskPath(spec)
		st, err := os.Stat(path)
		if err != nil {
			info.Available = false
			if !os.IsNotExist(err) {
				info.Error = err.Error()
			}
			out = append(out, info)
			continue
		}
		info.Available = true
		info.Size = st.Size()
		info.ModifiedAt = st.ModTime().UTC().Format("2006-01-02T15:04:05Z")
		// SHA-256 of small (<200 MB) files only; otherwise skip to avoid stalls.
		if st.Size() <= 200*1024*1024 {
			if sum, err := fileSHA256(path); err == nil {
				info.SHA256 = sum
			}
		}
		out = append(out, info)
	}
	writeJSON(w, out)
}

// Download streams the requested platform's collector to the client.
func (h *CollectorHandler) Download(w http.ResponseWriter, r *http.Request) {
	platform := chi.URLParam(r, "platform")
	var spec *collectorSpec
	for i := range collectorCatalog {
		if collectorCatalog[i].Platform == platform {
			spec = &collectorCatalog[i]
			break
		}
	}
	if spec == nil {
		http.Error(w, "unknown platform", http.StatusNotFound)
		return
	}

	path := h.diskPath(*spec)
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, fmt.Sprintf("collector for %s not bundled with this deployment", platform), http.StatusNotFound)
			return
		}
		httpError(w, err)
		return
	}
	if st.IsDir() {
		http.Error(w, "collector path is a directory", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", spec.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, spec.Filename))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, path)
}

func (h *CollectorHandler) diskPath(spec collectorSpec) string {
	return filepath.Join(h.CollectorsDir, spec.Platform, spec.Filename)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
