// Package main is the ResponseRay Linux artifact collector entry point. It mirrors the layout
// and manifest schema of the Windows collector so backend ingestion is identical.
package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/responseray/collector-linux/internal/collectors"
	"github.com/responseray/collector-linux/internal/fsutil"
	"github.com/responseray/collector-linux/internal/manifest"
)

const Version = "2026.4.26.2"

func main() {
	output := flag.String("output", ".", "Directory to write the resulting tar.gz archive into")
	skipFlag := flag.String("skip", "", "Comma-separated list of collector names to skip")
	includeMem := flag.Bool("include-memory", false, "Include memory and swap artifacts (large)")
	flag.Parse()

	banner()

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "[-] This tool must be run as root.")
		os.Exit(1)
	}

	hostname, _ := os.Hostname()
	now := time.Now()
	collectionDir := filepath.Join(os.TempDir(), fmt.Sprintf("ResponseRay_%s_%s", hostname, now.Format("20060102_150405")))
	if err := os.MkdirAll(collectionDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "[-] Failed to create collection dir:", err)
		os.Exit(1)
	}

	skip := map[string]bool{}
	for _, s := range strings.Split(*skipFlag, ",") {
		s = strings.TrimSpace(strings.ToLower(s))
		if s != "" {
			skip[s] = true
		}
	}

	fmt.Printf("[+] Hostname: %s\n", hostname)
	fmt.Printf("[+] Output:   %s\n", *output)
	if *includeMem {
		fmt.Printf("[+] Memory:   included (--include-memory)\n")
	}

	ctx := fsutil.NewContext(collectionDir, hostname, *includeMem)

	osVersion, _ := readFirstLine("/etc/os-release")
	if osVersion == "" {
		osVersion = runtime.GOOS + " " + runtime.GOARCH
	}

	m := &manifest.Manifest{
		CollectorVersion:    Version,
		Platform:            "linux",
		Hostname:            hostname,
		OsVersion:           osVersion,
		Domain:              "",
		CollectionTimestamp: now.UTC().Format(time.RFC3339),
		UserProfiles:        listUserProfiles(),
	}

	overallStart := time.Now()
	fmt.Println()
	fmt.Println("=== Collecting Artifacts ===")

	for _, c := range collectors.All {
		if skip[strings.ToLower(c.Name())] {
			fmt.Printf("    Skipping %s\n", c.Name())
			continue
		}
		runStart := time.Now()
		var res collectors.Result
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					res.Error = fmt.Sprintf("panic: %v", rec)
					res.Name = c.Name()
				}
			}()
			res = c.Collect(ctx)
		}()
		_ = runStart

		entry := manifest.CollectorResult{
			Name:           res.Name,
			FilesCollected: res.FilesCollected,
			BytesCollected: res.BytesCollected,
			ElapsedMs:      res.Elapsed.Milliseconds(),
			Error:          res.Error,
		}
		m.CollectorResults = append(m.CollectorResults, entry)

		if res.Error != "" {
			fmt.Printf("[!] %s: %s\n", c.Name(), res.Error)
		} else if res.FilesCollected > 0 {
			fmt.Printf("[+] %s: %d files (%s) in %.1fs\n", c.Name(), res.FilesCollected,
				fsutil.FormatSize(res.BytesCollected), res.Elapsed.Seconds())
		} else {
			fmt.Printf("    %s: nothing found\n", c.Name())
		}
	}

	for _, fe := range ctx.Files() {
		m.Files = append(m.Files, fe)
	}
	m.TotalFiles = len(m.Files)
	m.TotalBytes = ctx.TotalBytes()
	m.CollectionDurationSeconds = time.Since(overallStart).Seconds()

	if err := m.Save(filepath.Join(collectionDir, "manifest.json")); err != nil {
		fmt.Fprintln(os.Stderr, "[-] manifest save failed:", err)
	}

	fmt.Println()
	fmt.Println("=== Packaging ===")
	archive := filepath.Join(*output, fmt.Sprintf("%s_%s.tar.gz", hostname, now.Format("20060102_150405")))
	if err := makeTarGz(collectionDir, archive); err != nil {
		fmt.Fprintln(os.Stderr, "[-] archive failed:", err)
		os.Exit(1)
	}
	if size, err := fileSize(archive); err == nil {
		fmt.Printf("[+] Output: %s (%s)\n", archive, fsutil.FormatSize(size))
	}
	_ = os.RemoveAll(collectionDir)
}

func banner() {
	fmt.Printf(`
  ____                                      ____
 |  _ \ ___  ___ _ __   ___  _ __  ___  ___|  _ \ __ _ _   _
 | |_) / _ \/ __| '_ \ / _ \| '_ \/ __|/ _ \ |_) / _' | | | |
 |  _ <  __/\__ \ |_) | (_) | | | \__ \  __/  _ < (_| | |_| |
 |_| \_\___||___/ .__/ \___/|_| |_|___/\___|_| \_\__,_|\__, |
                |_|   Linux Artifact Collector         |___/
  Version %s
  %s

`, Version, time.Now().Format("2006-01-02 15:04:05"))
}

func readFirstLine(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	idx := strings.IndexByte(string(b), '\n')
	if idx < 0 {
		return string(b), nil
	}
	return string(b[:idx]), nil
}

func listUserProfiles() []string {
	out := []string{}
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, e.Name())
			}
		}
	}
	if _, err := os.Stat("/root"); err == nil {
		out = append(out, "root")
	}
	return out
}

func makeTarGz(srcDir, destPath string) error {
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
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
		rel, _ := filepath.Rel(srcDir, path)
		if rel == "." {
			return nil
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !d.IsDir() {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
		}
		return nil
	})
}

func fileSize(p string) (int64, error) {
	info, err := os.Stat(p)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// quiet the unused import warnings if they ever drift
var _ = exec.Command
