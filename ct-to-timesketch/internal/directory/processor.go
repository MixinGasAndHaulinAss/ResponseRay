package directory

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

// Process runs the full directory-mode pipeline on a ResponseRay Collector
// output directory. It returns the hostname extracted from the manifest.
func Process(dirPath, artifactDir string, conv *converter.Converter) (string, *cache.Index, error) {
	manifest, err := ParseManifest(dirPath)
	if err != nil {
		return "", nil, err
	}

	conv.Hostname = manifest.Hostname
	progress.Info(fmt.Sprintf("Host: %s", manifest.Hostname))
	progress.Info(fmt.Sprintf("Platform: %s", manifest.Platform))
	progress.Info(fmt.Sprintf("OS: %s", manifest.OsVersion))
	progress.Info(fmt.Sprintf("Domain: %s", manifest.Domain))
	progress.Info(fmt.Sprintf("Collection time: %s", manifest.CollectionTimestamp))
	progress.Info(fmt.Sprintf("Collector version: %s", manifest.CollectorVersion))
	progress.Info(fmt.Sprintf("Total files: %d (%s)", manifest.TotalFiles, converter.FormatBytes(manifest.TotalBytes)))
	if manifest.VssUsed {
		progress.Info(fmt.Sprintf("VSS shadow used: %s", manifest.VssPath))
	}

	for _, cr := range manifest.CollectorResults {
		if cr.Error != "" {
			progress.Warning(fmt.Sprintf("Collector %s failed: %s", cr.Name, cr.Error))
		}
	}

	// Step 1: Copy file-based artifacts to the artifacts directory
	progress.Header("COPY ARTIFACTS")
	if err := copyArtifacts(dirPath, artifactDir, manifest); err != nil {
		return manifest.Hostname, nil, fmt.Errorf("copy artifacts: %w", err)
	}

	// Step 2: Build cache index from the artifacts directory
	idx := &cache.Index{ArtifactsDir: artifactDir}
	n, err := idx.ScanArtifactDir()
	if err != nil {
		progress.Warning(fmt.Sprintf("Error scanning artifact dir: %v", err))
	}
	progress.Info(fmt.Sprintf("Indexed %d artifact files in %s", n, artifactDir))

	// Step 3: Run all registered extractors on the file artifacts
	names := extractors.ListNames()
	sort.Strings(names)
	for _, name := range names {
		if name == "entra" || name == "mdo" {
			continue
		}
		ext := extractors.Get(name)
		if ext == nil {
			continue
		}
		progress.Header(fmt.Sprintf("EXTRACTING: %s", ext.Description()))
		timer := progress.NewStepTimer(name)
		count, err := ext.Extract("", conv, idx)
		if err != nil {
			progress.Warning(fmt.Sprintf("%s: %v", name, err))
		} else if count > 0 {
			progress.Info(fmt.Sprintf("  Added %d events", count))
		}
		timer.Done()
	}

	// Step 4: Process live system state data
	progress.Header("LIVE SYSTEM STATE (collector JSON)")
	timer := progress.NewStepTimer("Live data")
	liveCount := ProcessLiveData(dirPath, conv, manifest.CollectionTimestamp)
	progress.Info(fmt.Sprintf("Live data: %d total events", liveCount))
	timer.Done()

	// Step 5: Process filesystem enumeration (MACB timeline)
	// Only use filesystem.jsonl if MFT extractor didn't produce events
	// (MFT provides better coverage: deleted files + $FN timestamps)
	mftEvents := conv.CountByType("file_timeline") + conv.CountByType("file_timeline_fn")
	if mftEvents == 0 {
		progress.Header("FILESYSTEM TIMELINE")
		timer = progress.NewStepTimer("Filesystem JSONL")
		fsCount := ProcessFilesystemJSONL(dirPath, conv)
		progress.Info(fmt.Sprintf("Filesystem: %d events", fsCount))
		timer.Done()
	} else {
		progress.Header("FILESYSTEM TIMELINE")
		progress.Info(fmt.Sprintf("Skipping filesystem.jsonl -- MFT parser already produced %d file timeline events", mftEvents))
	}

	return manifest.Hostname, idx, nil
}

// copyArtifacts copies file-based artifacts from the collector output
// to the target artifacts directory, preserving the subdirectory structure
// expected by the extractors.
func copyArtifacts(dirPath, artifactDir string, manifest *Manifest) error {
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return err
	}

	srcArtifacts := filepath.Join(dirPath, "artifacts")
	if _, err := os.Stat(srcArtifacts); os.IsNotExist(err) {
		progress.Warning("No artifacts/ directory found in collector output")
		return nil
	}

	copied := 0
	err := filepath.Walk(srcArtifacts, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return err
		}

		rel, _ := filepath.Rel(srcArtifacts, path)
		destPath := filepath.Join(artifactDir, rel)

		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return err
		}

		if err := copyFile(path, destPath); err != nil {
			progress.Warning(fmt.Sprintf("Failed to copy %s: %v", rel, err))
			return nil
		}
		copied++
		return nil
	})

	if err != nil {
		return err
	}

	// Also copy raw $MFT if present
	mftSrc := filepath.Join(dirPath, "mft", "$MFT")
	if fi, err := os.Stat(mftSrc); err == nil && !fi.IsDir() {
		mftDest := filepath.Join(artifactDir, "mft", "$MFT")
		os.MkdirAll(filepath.Dir(mftDest), 0o755)
		if err := copyFile(mftSrc, mftDest); err != nil {
			progress.Warning(fmt.Sprintf("Failed to copy $MFT: %v", err))
		} else {
			copied++
			progress.Info(fmt.Sprintf("Copied raw $MFT (%s)", converter.FormatBytes(fi.Size())))
		}
	}

	progress.Info(fmt.Sprintf("Copied %d artifact files to %s", copied, artifactDir))
	return nil
}

func copyFile(src, dst string) error {
	// Remove existing destination to avoid hard-link inode aliasing:
	// if a previous run hard-linked src→dst, os.Create(dst) would truncate
	// the shared inode, corrupting both src and dst.
	os.Remove(dst)

	if err := os.Link(src, dst); err == nil {
		return nil
	}

	sf, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sf.Close()

	df, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer df.Close()

	_, err = io.Copy(df, sf)
	return err
}
