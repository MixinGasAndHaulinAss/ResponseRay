// ResponseRay macOS collector entry point.
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/responseray/collector-macos/internal/collectors"
	"github.com/responseray/collector-macos/internal/fsutil"
	"github.com/responseray/collector-macos/internal/manifest"
)

const collectorVersion = "2026.4.30.1"

func main() {
	output := flag.String("output", "", "Output directory for the collection (defaults to /var/tmp/<host>-<timestamp>)")
	skipFlag := flag.String("skip", "", "Comma-separated collector names to skip (case-insensitive)")
	includeMemory := flag.Bool("include-memory", false, "Include swap/sleep image artifacts (large)")
	flag.Parse()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "WARNING: ResponseRay macOS collector should be run as root for full coverage.")
	}

	hostname, _ := os.Hostname()
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		hostname = "macos-host"
	}
	hostname = strings.ReplaceAll(hostname, " ", "_")

	ts := time.Now().UTC()
	stamp := ts.Format("20060102T150405Z")
	collectionName := fmt.Sprintf("ResponseRay_%s_%s", hostname, stamp)
	outDir := *output
	if outDir == "" {
		outDir = filepath.Join("/var/tmp", collectionName)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		log.Fatalf("create output dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, "artifacts"), 0o755); err != nil {
		log.Fatalf("create artifacts dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(outDir, "live"), 0o755); err != nil {
		log.Fatalf("create live dir: %v", err)
	}

	skip := map[string]struct{}{}
	for _, s := range strings.Split(*skipFlag, ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" {
			skip[s] = struct{}{}
		}
	}

	ctx := fsutil.NewContext(outDir, hostname, *includeMemory)

	m := &manifest.Manifest{
		CollectorVersion:    collectorVersion,
		Platform:            "macos",
		Hostname:            hostname,
		CollectionTimestamp: ts.Format(time.RFC3339),
	}

	if v, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
		m.OsVersion = "macOS " + strings.TrimSpace(string(v))
	}
	if homes := listUserHomes(); len(homes) > 0 {
		m.UserProfiles = homes
	}

	overallStart := time.Now()
	for _, c := range collectors.All {
		name := c.Name()
		if _, drop := skip[strings.ToLower(name)]; drop {
			log.Printf("[skip] %s", name)
			continue
		}
		filesBefore := len(ctx.Files())
		bytesBefore := ctx.TotalBytes()
		t0 := time.Now()
		err := c.Run(ctx)
		elapsed := time.Since(t0)
		filesAfter := len(ctx.Files())
		bytesAfter := ctx.TotalBytes()
		res := manifest.CollectorResult{
			Name:           name,
			FilesCollected: filesAfter - filesBefore,
			BytesCollected: bytesAfter - bytesBefore,
			ElapsedMs:      elapsed.Milliseconds(),
		}
		if err != nil {
			res.Error = err.Error()
			log.Printf("[err]  %-22s %s", name, err)
		} else {
			log.Printf("[ok]   %-22s files=%d bytes=%s elapsed=%dms",
				name, res.FilesCollected, fsutil.FormatSize(res.BytesCollected), res.ElapsedMs)
		}
		m.CollectorResults = append(m.CollectorResults, res)
	}

	m.Files = ctx.Files()
	m.TotalFiles = len(m.Files)
	m.TotalBytes = ctx.TotalBytes()
	m.CollectionDurationSeconds = time.Since(overallStart).Seconds()

	if err := m.Save(filepath.Join(outDir, "manifest.json")); err != nil {
		log.Fatalf("save manifest: %v", err)
	}

	archive := outDir + ".tar.gz"
	if err := writeTarGz(archive, outDir); err != nil {
		log.Fatalf("create archive: %v", err)
	}
	if info, err := os.Stat(archive); err == nil {
		fmt.Printf("Collection archive: %s (%s)\n", archive, fsutil.FormatSize(info.Size()))
	}
}

func writeTarGz(archivePath, sourceDir string) error {
	out, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	parent := filepath.Dir(sourceDir)
	return filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

func listUserHomes() []string {
	var homes []string
	entries, err := os.ReadDir("/Users")
	if err != nil {
		return homes
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "Shared" || strings.HasPrefix(name, ".") {
			continue
		}
		homes = append(homes, "/Users/"+name)
	}
	return homes
}
