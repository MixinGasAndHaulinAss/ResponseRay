package collectoringest

import (
	"fmt"
	"log"
	"strings"
)

// Run reads the manifest from the extracted collector directory, dispatches
// to the right per-platform parser, and writes timeline.jsonl to outputPath.
//
// Returns the manifest hostname and the number of events written. If the
// platform is "windows" or unrecognized, Run returns ErrUnsupportedPlatform
// so the worker can fall back to ct-to-timesketch (which still owns the
// Windows artifact extractors).
func Run(extractedDir, outputPath string) (hostname string, count int, err error) {
	manifest, err := ParseManifest(extractedDir)
	if err != nil {
		return "", 0, err
	}
	hostname = manifest.Hostname
	platform := strings.ToLower(strings.TrimSpace(manifest.Platform))

	log.Printf("collectoringest: host=%s platform=%s os=%s", manifest.Hostname, platform, manifest.OsVersion)

	em := NewEmitter(manifest.Hostname)

	switch platform {
	case "macos":
		ProcessMacOS(em, extractedDir, manifest.CollectionTimestamp)
	default:
		return hostname, 0, &ErrUnsupportedPlatform{Platform: platform}
	}

	n, err := em.WriteJSONL(outputPath)
	if err != nil {
		return hostname, 0, fmt.Errorf("write jsonl: %w", err)
	}
	log.Printf("collectoringest: wrote %d events to %s", n, outputPath)
	for et, c := range em.Stats() {
		log.Printf("collectoringest:   %-25s %d", et, c)
	}
	return hostname, n, nil
}

// ErrUnsupportedPlatform is returned when Run is invoked on a manifest whose
// platform isn't (yet) handled in-process. The worker uses this signal to
// fall back to the ct-to-timesketch path that's still in use for Windows.
type ErrUnsupportedPlatform struct{ Platform string }

func (e *ErrUnsupportedPlatform) Error() string {
	return fmt.Sprintf("collectoringest: platform %q not supported in-process", e.Platform)
}

// IsUnsupportedPlatform reports whether err signals that the manifest's
// platform isn't handled by collectoringest.
func IsUnsupportedPlatform(err error) bool {
	_, ok := err.(*ErrUnsupportedPlatform)
	return ok
}
