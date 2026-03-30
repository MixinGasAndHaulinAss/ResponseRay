package cache

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

// EnsureCache decompresses a .json.gz to .json.cache if needed and returns the cache path.
func EnsureCache(capturePath string) (string, error) {
	if strings.HasSuffix(capturePath, ".cache") {
		if _, err := os.Stat(capturePath); err != nil {
			return "", fmt.Errorf("cache file not found: %s", capturePath)
		}
		return capturePath, nil
	}

	cachePath := CachePath(capturePath)
	if _, err := os.Stat(cachePath); err == nil {
		return cachePath, nil
	}

	info, err := os.Stat(capturePath)
	if err != nil {
		return "", err
	}
	progress.Info(fmt.Sprintf("Decompressing %s (%.0f MB compressed)...",
		filepath.Base(capturePath), float64(info.Size())/(1024*1024)))

	src, err := os.Open(capturePath)
	if err != nil {
		return "", err
	}
	defer src.Close()

	gz, err := gzip.NewReader(src)
	if err != nil {
		return "", fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	dst, err := os.Create(cachePath)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	buf := make([]byte, 50*1024*1024)
	var written int64
	for {
		n, readErr := gz.Read(buf)
		if n > 0 {
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return "", wErr
			}
			written += int64(n)
			progress.ProgressLine("Decompressed: %.0f MB", float64(written)/(1024*1024))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", readErr
		}
	}
	progress.ProgressDone()
	return cachePath, nil
}

// CachePath returns the .json.cache path for a capture file.
func CachePath(capturePath string) string {
	dir := filepath.Dir(capturePath)
	base := filepath.Base(capturePath)
	if strings.HasSuffix(base, ".gz") {
		base = base[:len(base)-3] + ".cache"
	} else {
		base += ".cache"
	}
	return filepath.Join(dir, base)
}

var reHostname = regexp.MustCompile(`"localHostName"\s*:\s*"([^"]+)"`)

// GetHostname extracts the hostname from the first 100 MB of the cache file.
func GetHostname(cachePath string) string {
	f, err := os.Open(cachePath)
	if err != nil {
		return "unknown"
	}
	defer f.Close()

	buf := make([]byte, 100*1024*1024)
	n, _ := f.Read(buf)
	if m := reHostname.FindSubmatch(buf[:n]); m != nil {
		return string(m[1])
	}
	return "unknown"
}
