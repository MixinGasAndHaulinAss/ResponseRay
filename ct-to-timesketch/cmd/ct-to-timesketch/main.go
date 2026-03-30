package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/directory"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/help"
	"github.com/NCLGISA/ct-to-timesketch/internal/postprocess"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
	"github.com/NCLGISA/ct-to-timesketch/internal/scanner"

	_ "github.com/NCLGISA/ct-to-timesketch/internal/extractors/all"
)

func main() {
	os.Exit(run())
}

// reorderArgs moves positional arguments after flags so Go's flag package
// parses everything correctly regardless of argument order.
func reorderArgs() {
	raw := os.Args[1:]
	stringFlags := map[string]bool{
		"-o": true, "--output": true, "-output": true,
		"--artifacts-dir": true, "-artifacts-dir": true,
		"--hayabusa-path": true, "-hayabusa-path": true,
		"--cloudrules-path": true, "-cloudrules-path": true,
		"--directory": true, "-directory": true,
	}
	var flags, positional []string
	for i := 0; i < len(raw); i++ {
		if strings.HasPrefix(raw[i], "-") {
			flags = append(flags, raw[i])
			if !strings.Contains(raw[i], "=") && stringFlags[raw[i]] && i+1 < len(raw) {
				i++
				flags = append(flags, raw[i])
			}
		} else {
			positional = append(positional, raw[i])
		}
	}
	os.Args = append([]string{os.Args[0]}, append(flags, positional...)...)
}

func run() int {
	if len(os.Args) >= 2 && os.Args[1] == "help" {
		topic := ""
		if len(os.Args) >= 3 {
			topic = os.Args[2]
		}
		help.Show(topic)
		return 0
	}

	reorderArgs()

	var (
		output         string
		skipBase       bool
		listExtract    bool
		version        bool
		artifactDir    string
		entraMode      bool
		mdoMode        bool
		hayabusa       bool
		hayabusaPath   string
		cloudrules     bool
		cloudrulesPath string
		directoryDir   string
	)

	flag.StringVar(&output, "output", "", "Output JSONL file (default: reports/<hostname>_timeline.jsonl)")
	flag.StringVar(&output, "o", "", "Output JSONL file (shorthand)")
	flag.BoolVar(&skipBase, "skip-base", false, "Skip streaming scan (re-run extractors against existing artifacts)")
	flag.BoolVar(&listExtract, "list-extractors", false, "List available extractors and exit")
	flag.BoolVar(&version, "version", false, "Print version and exit")
	flag.StringVar(&artifactDir, "artifacts-dir", "", "Directory for extracted native artifacts (default: artifacts/<hostname>/)")
	flag.BoolVar(&entraMode, "entra", false, "Input is Entra ID / Azure AD sign-in JSON")
	flag.BoolVar(&mdoMode, "mdo", false, "Input is Microsoft Defender for Office 365 CSV")
	flag.BoolVar(&hayabusa, "hayabusa", false, "Run Hayabusa Sigma threat detection on EVTX artifacts")
	flag.StringVar(&hayabusaPath, "hayabusa-path", "", "Path to Hayabusa binary (auto-detected if omitted)")
	flag.BoolVar(&cloudrules, "cloudrules", false, "Run CyberTriage CloudRules threat detection on timeline events")
	flag.StringVar(&cloudrulesPath, "cloudrules-path", "", "Path to CloudRules json.gz (auto-detected if omitted)")
	flag.StringVar(&directoryDir, "directory", "", "Process a ResponseRay Collector output directory instead of a CyberTriage JSON file")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ct-to-timesketch <capture.json.gz> [options]\n")
		fmt.Fprintf(os.Stderr, "       ct-to-timesketch --directory <collector-output-dir> [options]\n\n")
		fmt.Fprintf(os.Stderr, "All forensic extractors run automatically. No --parse flags needed.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if version {
		fmt.Println("ct-to-timesketch 2026.03.19.1 (Go, streaming, full-extraction, CloudRules, directory-mode, MFT-parser)")
		return 0
	}

	if listExtract {
		fmt.Println("\nAvailable Extractors (all run automatically):")
		fmt.Println(strings.Repeat("-", 60))
		names := extractors.ListNames()
		sort.Strings(names)
		for _, name := range names {
			ext := extractors.Get(name)
			fmt.Printf("  %-20s %s\n", name, ext.Description())
		}
		return 0
	}

	// Directory mode: process a ResponseRay Collector output directory
	if directoryDir != "" {
		return runDirectoryMode(directoryDir, output, artifactDir, hayabusa, hayabusaPath, cloudrules, cloudrulesPath)
	}

	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: capture file argument required (or use --directory)")
		flag.Usage()
		return 1
	}
	capturePath := args[0]

	if _, err := os.Stat(capturePath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: File not found: %s\n", capturePath)
		return 1
	}

	totalStart := time.Now()

	isEntra := strings.HasSuffix(capturePath, ".json") && entraMode
	isMDO := strings.HasSuffix(capturePath, ".csv") && mdoMode
	isCloudDir := isDir(capturePath) && (entraMode || mdoMode)

	var cachePath, hostname string
	var cacheIdx *cache.Index

	if isEntra || isMDO || isCloudDir {
		cachePath = capturePath
		hostname = deriveHostnameFromPath(capturePath)
	} else {
		timer := progress.NewStepTimer("Decompress/cache")
		var err error
		cachePath, err = cache.EnsureCache(capturePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}
		timer.Done()
		hostname = cache.GetHostname(cachePath)
	}

	fmt.Fprintf(os.Stderr, "\nHost: %s\n", hostname)
	conv := converter.New(hostname)

	if artifactDir == "" {
		artifactDir = filepath.Join("artifacts", hostname)
	}

	// Streaming scan: single-pass JSON decoder that creates timeline events
	// and exports collected files as native artifacts to disk
	if !isEntra && !isMDO && !isCloudDir {
		if !skipBase {
			progress.Header("STREAMING SCAN (single-pass JSON decoder)")
			timer := progress.NewStepTimer("Streaming scan")
			result, err := scanner.StreamingScan(cachePath, artifactDir, conv)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				return 1
			}
			timer.Done()

			cacheIdx = &cache.Index{
				ArtifactsDir:  artifactDir,
				ArtifactFiles: result.ArtifactFiles,
				FileSize:      result.FileSize,
			}
			progress.Info(fmt.Sprintf("Artifacts: %d native files in %s", result.FilesWritten, artifactDir))
		} else {
			cacheIdx = &cache.Index{ArtifactsDir: artifactDir}
			if n, err := cacheIdx.ScanArtifactDir(); err == nil && n > 0 {
				progress.Info(fmt.Sprintf("Discovered %d existing artifacts in %s", n, artifactDir))
			}
		}
	}

	// Run all registered extractors unconditionally
	names := extractors.ListNames()
	sort.Strings(names)
	for _, name := range names {
		// Cloud-only extractors require explicit mode flags
		if name == "entra" && !entraMode {
			continue
		}
		if name == "mdo" && !mdoMode {
			continue
		}

		ext := extractors.Get(name)
		if ext == nil {
			continue
		}
		progress.Header(fmt.Sprintf("EXTRACTING: %s", ext.Description()))
		timer := progress.NewStepTimer(name)
		n, err := ext.Extract(cachePath, conv, cacheIdx)
		if err != nil {
			progress.Warning(fmt.Sprintf("%s: %v", name, err))
		} else if n > 0 {
			progress.Info(fmt.Sprintf("  Added %d events", n))
		}
		timer.Done()
	}

	// Hayabusa threat detection (Sigma rules against native EVTX artifacts)
	if hayabusa {
		progress.Header("HAYABUSA THREAT DETECTION (Sigma rules)")
		timer := progress.NewStepTimer("Hayabusa")
		tagged, err := postprocess.RunHayabusa(artifactDir, hayabusaPath, conv)
		if err != nil {
			progress.Warning(fmt.Sprintf("Hayabusa: %v", err))
		} else if tagged > 0 {
			progress.Info(fmt.Sprintf("  Tagged %d events with Sigma detections", tagged))
		}
		timer.Done()
	}

	// CloudRules threat detection (CyberTriage rules against timeline events)
	if cloudrules {
		progress.Header("CLOUDRULES THREAT DETECTION (CyberTriage rules)")
		timer := progress.NewStepTimer("CloudRules")
		tagged, err := postprocess.RunCloudRules(cloudrulesPath, conv)
		if err != nil {
			progress.Warning(fmt.Sprintf("CloudRules: %v", err))
		} else if tagged > 0 {
			progress.Info(fmt.Sprintf("  Tagged %d events with CloudRules detections", tagged))
		}
		timer.Done()
	}

	// Write output
	if output == "" {
		os.MkdirAll("reports", 0o755)
		output = filepath.Join("reports", hostname+"_timeline.jsonl")
	} else {
		if dir := filepath.Dir(output); dir != "" && dir != "." {
			os.MkdirAll(dir, 0o755)
		}
	}

	timer := progress.NewStepTimer("Write JSONL")
	eventCount, err := conv.WriteJSONL(output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing JSONL: %v\n", err)
		return 1
	}
	timer.Done()

	totalElapsed := time.Since(totalStart)
	progress.PrintSummary(conv.GetSummary(), eventCount, totalElapsed)
	progress.Success(fmt.Sprintf("Timeline saved to: %s", output))
	progress.Info(fmt.Sprintf("Native artifacts: %s", artifactDir))
	progress.Info("Ready for import into Timesketch!")
	return 0
}

// runDirectoryMode processes a ResponseRay Collector output directory.
func runDirectoryMode(dirPath, output, artifactDir string, hayabusa bool, hayabusaPath string, cloudrules bool, cloudrulesPath string) int {
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: Directory not found: %s\n", dirPath)
		return 1
	}

	totalStart := time.Now()
	progress.Header("RESPONSERAY COLLECTOR DIRECTORY MODE")

	conv := converter.New("unknown")

	if artifactDir == "" {
		artifactDir = filepath.Join("artifacts", "collector")
	}

	hostname, _, err := directory.Process(dirPath, artifactDir, conv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return 1
	}

	if hayabusa {
		progress.Header("HAYABUSA THREAT DETECTION (Sigma rules)")
		timer := progress.NewStepTimer("Hayabusa")
		tagged, err := postprocess.RunHayabusa(artifactDir, hayabusaPath, conv)
		if err != nil {
			progress.Warning(fmt.Sprintf("Hayabusa: %v", err))
		} else if tagged > 0 {
			progress.Info(fmt.Sprintf("  Tagged %d events with Sigma detections", tagged))
		}
		timer.Done()
	}

	if cloudrules {
		progress.Header("CLOUDRULES THREAT DETECTION (CyberTriage rules)")
		timer := progress.NewStepTimer("CloudRules")
		tagged, err := postprocess.RunCloudRules(cloudrulesPath, conv)
		if err != nil {
			progress.Warning(fmt.Sprintf("CloudRules: %v", err))
		} else if tagged > 0 {
			progress.Info(fmt.Sprintf("  Tagged %d events with CloudRules detections", tagged))
		}
		timer.Done()
	}

	if output == "" {
		os.MkdirAll("reports", 0o755)
		output = filepath.Join("reports", hostname+"_timeline.jsonl")
	} else {
		if dir := filepath.Dir(output); dir != "" && dir != "." {
			os.MkdirAll(dir, 0o755)
		}
	}

	timer := progress.NewStepTimer("Write JSONL")
	eventCount, err := conv.WriteJSONL(output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error writing JSONL: %v\n", err)
		return 1
	}
	timer.Done()

	totalElapsed := time.Since(totalStart)
	progress.PrintSummary(conv.GetSummary(), eventCount, totalElapsed)
	progress.Success(fmt.Sprintf("Timeline saved to: %s", output))
	progress.Info(fmt.Sprintf("Native artifacts: %s", artifactDir))
	progress.Info("Ready for import into Timesketch!")
	return 0
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func deriveHostnameFromPath(capturePath string) string {
	if isDir(capturePath) {
		abs, _ := filepath.Abs(capturePath)
		name := filepath.Base(strings.TrimRight(abs, "/\\"))
		return strings.ReplaceAll(strings.ToLower(name), " ", "_")
	}
	dir := filepath.Base(filepath.Dir(filepath.Clean(capturePath)))
	if dir != "" && dir != "." {
		return strings.ReplaceAll(strings.ToLower(dir), " ", "_")
	}
	base := strings.TrimSuffix(filepath.Base(capturePath), filepath.Ext(capturePath))
	return strings.ReplaceAll(strings.ToLower(base), " ", "_")
}
