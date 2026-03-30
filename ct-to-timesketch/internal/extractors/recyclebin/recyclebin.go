package recyclebin

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

func init() { extractors.Register(&Extractor{}) }

type Extractor struct{}

func (e *Extractor) Name() string        { return "recyclebin" }
func (e *Extractor) Description() string { return "Recycle Bin $I file metadata" }

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	if idx == nil {
		return 0, nil
	}
	files, err := idx.GetCollectedFiles(`\$I`, "")
	if err != nil {
		return 0, err
	}
	added := 0
	for _, f := range files {
		decoded, err := extractors.GetFileContent(f)
		if err != nil || len(decoded) < 28 {
			continue
		}
		entry := parseIFile(decoded)
		if entry == nil {
			continue
		}
		ts := converter.FiletimeToISO(entry.deletionTime)
		if ts == "" {
			continue
		}
		msg := fmt.Sprintf("Deleted: %s (%.1f KB)", entry.path, float64(entry.fileSize)/1024)
		if conv.AddEvent(ts, "File Deletion Time", msg, "file_deleted",
			"CT-RecycleBin", "CyberTriage Recycle Bin",
			"windows:shell_items:recycle_bin", map[string]interface{}{
				"file_path": entry.path,
				"file_size": entry.fileSize,
				"file_name": f.Filename,
			}) {
			added++
		}
	}
	progress.Info(fmt.Sprintf("Recycle Bin: %d deleted files", added))
	return added, nil
}

type iFileEntry struct {
	fileSize     int64
	deletionTime int64
	path         string
}

func parseIFile(data []byte) *iFileEntry {
	if len(data) < 28 {
		return nil
	}
	version := binary.LittleEndian.Uint64(data[0:8])
	entry := &iFileEntry{}

	if version == 1 {
		// V1: header(8) + size(8) + deletionTime(8) + path(UTF-16LE)
		entry.fileSize = int64(binary.LittleEndian.Uint64(data[8:16]))
		entry.deletionTime = int64(binary.LittleEndian.Uint64(data[16:24]))
		if len(data) > 24 {
			entry.path = decodeUTF16LE(data[24:])
		}
	} else if version == 2 {
		// V2: header(8) + size(8) + deletionTime(8) + pathLen(4) + path(UTF-16LE)
		if len(data) < 32 {
			return nil
		}
		entry.fileSize = int64(binary.LittleEndian.Uint64(data[8:16]))
		entry.deletionTime = int64(binary.LittleEndian.Uint64(data[16:24]))
		if len(data) > 28 {
			entry.path = decodeUTF16LE(data[28:])
		}
	} else {
		return nil
	}
	return entry
}

func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// Ensure even length
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	// Trim null terminators
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}
