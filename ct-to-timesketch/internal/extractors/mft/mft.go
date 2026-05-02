package mft

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

func init() { extractors.Register(&Extractor{}) }

const (
	recordSize    = 1024
	magicFILE     = 0x454C4946 // "FILE"
	attrStdInfo   = 0x10
	attrFileName  = 0x30
	attrEnd       = 0xFFFFFFFF
	flagInUse     = 0x01
	flagDirectory = 0x02
	nsDOS         = 2
	filetimeEpoch = 116444736000000000 // 100ns intervals from 1601 to 1970
)

type mftEntry struct {
	recordNum  uint32
	baseRef    uint32
	flags      uint16
	siCreated  time.Time
	siModified time.Time
	siChanged  time.Time
	siAccessed time.Time
	fnCreated  time.Time
	fnModified time.Time
	fnChanged  time.Time
	fnAccessed time.Time
	fileName   string
	parentRef  uint64
	fileSize   int64
	hasSI      bool
	hasFN      bool
}

type Extractor struct{}

func (e *Extractor) Name() string { return "mft" }
func (e *Extractor) Description() string {
	return "Raw $MFT parsing for file timeline with $SI and $FN timestamps"
}

func (e *Extractor) Extract(inputPath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	mftFiles := findAllMFTs(idx)
	if len(mftFiles) == 0 {
		return 0, nil
	}
	totalAdded := 0
	for _, mf := range mftFiles {
		progress.Info(fmt.Sprintf("Processing $MFT for %s: drive", mf.driveLetter))
		n, err := ParseMFT(mf.path, mf.driveLetter, conv)
		if err != nil {
			progress.Warning(fmt.Sprintf("$MFT %s: %v", mf.driveLetter, err))
			continue
		}
		totalAdded += n
	}
	return totalAdded, nil
}

type mftFile struct {
	path        string
	driveLetter string // e.g. "C", "D"
}

func findAllMFTs(idx *cache.Index) []mftFile {
	if idx == nil {
		return nil
	}
	var results []mftFile

	// Primary C: drive MFT (backward compatible names)
	for _, name := range []string{
		filepath.Join(idx.ArtifactsDir, "mft", "$MFT"),
		filepath.Join(idx.ArtifactsDir, "$MFT"),
	} {
		if fi, err := os.Stat(name); err == nil && fi.Size() > 0 {
			results = append(results, mftFile{path: name, driveLetter: "C"})
			break
		}
	}

	// Additional drives: $MFT_D, $MFT_E, etc.
	mftDir := filepath.Join(idx.ArtifactsDir, "mft")
	if entries, err := os.ReadDir(mftDir); err == nil {
		for _, de := range entries {
			name := de.Name()
			if !strings.HasPrefix(name, "$MFT_") || len(name) != 6 {
				continue
			}
			letter := string(name[5])
			if letter >= "A" && letter <= "Z" {
				full := filepath.Join(mftDir, name)
				if fi, err := os.Stat(full); err == nil && fi.Size() > 0 {
					results = append(results, mftFile{path: full, driveLetter: letter})
				}
			}
		}
	}

	return results
}

// ParseMFT reads a raw $MFT file and generates $SI + $FN timeline events.
// driveLetter is used as the path prefix (e.g. "C" -> "C:\...").
func ParseMFT(path string, driveLetter string, conv *converter.Converter) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open $MFT: %w", err)
	}
	defer f.Close()

	fi, _ := f.Stat()
	totalRecords := fi.Size() / recordSize
	progress.Info(fmt.Sprintf("Parsing raw $MFT (%s, ~%d records)", converter.FormatBytes(fi.Size()), totalRecords))

	// Pass 1: build directory tree for path resolution
	entries := make(map[uint32]*mftEntry)
	buf := make([]byte, recordSize)
	recordNum := uint32(0)

	for {
		_, err := io.ReadFull(f, buf)
		if err != nil {
			break
		}

		entry := parseRecord(buf, recordNum)
		if entry != nil && entry.hasFN {
			if entry.baseRef != 0 {
				// Extension record: merge $FILE_NAME into the base record
				base, ok := entries[entry.baseRef]
				if ok {
					if !base.hasFN {
						base.fileName = entry.fileName
						base.parentRef = entry.parentRef
						base.fnCreated = entry.fnCreated
						base.fnModified = entry.fnModified
						base.fnChanged = entry.fnChanged
						base.fnAccessed = entry.fnAccessed
						base.hasFN = true
					}
				} else {
					// Base not yet seen; store under base record number
					entry.recordNum = entry.baseRef
					entries[entry.baseRef] = entry
				}
			} else {
				entries[recordNum] = entry
			}
		} else if entry != nil && !entry.hasFN && entry.baseRef == 0 {
			// Base record without $FN (may have extension records later)
			if existing, exists := entries[recordNum]; exists {
				// Extension record was already stored here; merge $SI from base
				if entry.hasSI && !existing.hasSI {
					existing.siCreated = entry.siCreated
					existing.siModified = entry.siModified
					existing.siChanged = entry.siChanged
					existing.siAccessed = entry.siAccessed
					existing.hasSI = true
					existing.flags = entry.flags
				}
			} else {
				entries[recordNum] = entry
			}
		}
		recordNum++

		if recordNum%500000 == 0 {
			progress.ProgressLine("MFT Pass 1: %d / %d records...", recordNum, totalRecords)
		}
	}

	progress.Info(fmt.Sprintf("  Pass 1 complete: %d active entries", len(entries)))

	// Pass 2: resolve paths and emit events
	added := 0
	for _, entry := range entries {
		fullPath := resolvePath(entries, entry, driveLetter)
		if fullPath == "" {
			continue
		}

		isDir := entry.flags&flagDirectory != 0
		prefix := "File"
		metaType := "File"
		if isDir {
			prefix = "Directory"
			metaType = "Dir"
		}

		filePath, fileName := splitMFTPath(fullPath)

		attrs := map[string]interface{}{
			"file_path": filePath,
			"file_name": fileName,
			"file_size": entry.fileSize,
			"full_path": fullPath,
			"meta_type": metaType,
		}

		// $STANDARD_INFORMATION timestamps → file_timeline
		if entry.hasSI {
			siFields := []struct {
				ts   time.Time
				desc string
			}{
				{entry.siModified, "File Modified"},
				{entry.siCreated, "File Created"},
				{entry.siAccessed, "File Accessed"},
				{entry.siChanged, "MFT Entry Changed"},
			}
			for _, sf := range siFields {
				if sf.ts.IsZero() || sf.ts.Year() < 1980 {
					continue
				}
				cp := copyAttrs(attrs)
				ts := sf.ts.UTC().Format("2006-01-02T15:04:05+00:00")
				if conv.AddEvent(ts, sf.desc, prefix+": "+fullPath, "file_timeline",
					"RR-MFT", "ResponseRay MFT - $STANDARD_INFORMATION",
					"fs:stat:ntfs:$standard_information", cp) {
					added++
				}
			}
		}

		// $FILE_NAME timestamps → file_timeline_fn
		if entry.hasFN {
			fnFields := []struct {
				ts   time.Time
				desc string
			}{
				{entry.fnModified, "File Modified ($FN)"},
				{entry.fnCreated, "File Created ($FN)"},
				{entry.fnAccessed, "File Accessed ($FN)"},
				{entry.fnChanged, "MFT Entry Changed ($FN)"},
			}
			for _, ff := range fnFields {
				if ff.ts.IsZero() || ff.ts.Year() < 1980 {
					continue
				}
				cp := copyAttrs(attrs)
				cp["timestompNote"] = "Compare with SI timestamps for timestomping detection"
				ts := ff.ts.UTC().Format("2006-01-02T15:04:05+00:00")
				if conv.AddEvent(ts, ff.desc, prefix+" ($FN): "+fullPath, "file_timeline_fn",
					"RR-MFT", "ResponseRay MFT - $FILE_NAME",
					"fs:stat:ntfs:$file_name", cp) {
					added++
				}
			}
		}
	}

	return added, nil
}

// applyFixups restores the original sector-end bytes that NTFS replaces with
// the update sequence number for integrity verification.
func applyFixups(buf []byte) bool {
	if len(buf) < 48 {
		return false
	}
	fixupOffset := int(binary.LittleEndian.Uint16(buf[4:6]))
	fixupCount := int(binary.LittleEndian.Uint16(buf[6:8]))
	if fixupCount < 2 || fixupOffset+fixupCount*2 > len(buf) {
		return false
	}
	usn := binary.LittleEndian.Uint16(buf[fixupOffset : fixupOffset+2])
	for i := 1; i < fixupCount; i++ {
		sectorEnd := i*512 - 2
		if sectorEnd+1 >= len(buf) {
			break
		}
		if binary.LittleEndian.Uint16(buf[sectorEnd:sectorEnd+2]) != usn {
			return false
		}
		orig := binary.LittleEndian.Uint16(buf[fixupOffset+i*2 : fixupOffset+i*2+2])
		binary.LittleEndian.PutUint16(buf[sectorEnd:sectorEnd+2], orig)
	}
	return true
}

func parseRecord(buf []byte, recordNum uint32) *mftEntry {
	if len(buf) < 48 {
		return nil
	}

	magic := binary.LittleEndian.Uint32(buf[0:4])
	if magic != magicFILE {
		return nil
	}

	if !applyFixups(buf) {
		return nil
	}

	flags := binary.LittleEndian.Uint16(buf[22:24])
	if flags&flagInUse == 0 {
		return nil
	}

	firstAttrOffset := binary.LittleEndian.Uint16(buf[20:22])
	if firstAttrOffset >= recordSize || firstAttrOffset < 42 {
		return nil
	}

	baseRef := uint32(binary.LittleEndian.Uint64(buf[32:40]) & 0x0000FFFFFFFFFFFF)

	entry := &mftEntry{
		recordNum: recordNum,
		baseRef:   baseRef,
		flags:     flags,
	}

	offset := int(firstAttrOffset)
	for offset+8 < recordSize {
		attrType := binary.LittleEndian.Uint32(buf[offset : offset+4])
		if attrType == attrEnd || attrType == 0 {
			break
		}

		attrLen := int(binary.LittleEndian.Uint32(buf[offset+4 : offset+8]))
		if attrLen < 16 || offset+attrLen > recordSize {
			break
		}

		nonResident := buf[offset+8]
		if nonResident == 0 {
			contentSize := int(binary.LittleEndian.Uint32(buf[offset+16 : offset+20]))
			contentOffset := int(binary.LittleEndian.Uint16(buf[offset+20 : offset+22]))
			dataStart := offset + contentOffset

			if dataStart+contentSize <= recordSize {
				data := buf[dataStart : dataStart+contentSize]

				switch attrType {
				case attrStdInfo:
					parseStdInfo(data, entry)
				case attrFileName:
					parseFN(data, entry)
				}
			}
		}

		offset += attrLen
	}

	return entry
}

func parseStdInfo(data []byte, entry *mftEntry) {
	if len(data) < 32 {
		return
	}
	entry.siCreated = filetimeToTime(binary.LittleEndian.Uint64(data[0:8]))
	entry.siModified = filetimeToTime(binary.LittleEndian.Uint64(data[8:16]))
	entry.siChanged = filetimeToTime(binary.LittleEndian.Uint64(data[16:24]))
	entry.siAccessed = filetimeToTime(binary.LittleEndian.Uint64(data[24:32]))
	entry.hasSI = true
}

func parseFN(data []byte, entry *mftEntry) {
	if len(data) < 66 {
		return
	}

	ns := data[65]
	// Skip DOS-only short names; prefer Win32 or Win32+DOS
	if ns == nsDOS && entry.hasFN {
		return
	}

	entry.parentRef = binary.LittleEndian.Uint64(data[0:8]) & 0x0000FFFFFFFFFFFF
	entry.fnCreated = filetimeToTime(binary.LittleEndian.Uint64(data[8:16]))
	entry.fnModified = filetimeToTime(binary.LittleEndian.Uint64(data[16:24]))
	entry.fnChanged = filetimeToTime(binary.LittleEndian.Uint64(data[24:32]))
	entry.fnAccessed = filetimeToTime(binary.LittleEndian.Uint64(data[32:40]))
	entry.fileSize = int64(binary.LittleEndian.Uint64(data[48:56]))

	nameLen := int(data[64])
	nameStart := 66
	if nameStart+nameLen*2 <= len(data) {
		entry.fileName = decodeUTF16(data[nameStart : nameStart+nameLen*2])
	}
	entry.hasFN = true
}

func filetimeToTime(ft uint64) time.Time {
	if ft == 0 || ft < filetimeEpoch {
		return time.Time{}
	}
	nsec := (int64(ft) - filetimeEpoch) * 100
	return time.Unix(0, nsec).UTC()
}

func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	return string(utf16.Decode(u16))
}

func resolvePath(entries map[uint32]*mftEntry, entry *mftEntry, driveLetter string) string {
	parts := []string{entry.fileName}
	seen := map[uint32]bool{entry.recordNum: true}
	current := entry

	for {
		parentNum := uint32(current.parentRef & 0x0000FFFFFFFFFFFF)
		if parentNum == 5 {
			break
		}
		if seen[parentNum] {
			return ""
		}
		seen[parentNum] = true

		parent, ok := entries[parentNum]
		if !ok || parent.fileName == "" {
			return ""
		}

		parts = append([]string{parent.fileName}, parts...)
		current = parent
	}

	return driveLetter + ":\\" + strings.Join(parts, "\\")
}

// splitMFTPath converts a Windows-style MFT path like "C:\Windows\System32\file.dll"
// into the (parentDir, baseName) pair the filesystem browser expects:
//
//	file_path = "/c/windows/system32/"   (lowercase, forward slashes, drive letter as top-level dir)
//	file_name = "file.dll"              (original case preserved)
func splitMFTPath(fullPath string) (string, string) {
	normalized := strings.ReplaceAll(fullPath, "\\", "/")
	if len(normalized) >= 2 && normalized[1] == ':' {
		drive := strings.ToLower(string(normalized[0]))
		normalized = "/" + drive + normalized[2:]
	}
	idx := strings.LastIndex(normalized, "/")
	if idx < 0 {
		return "/", normalized
	}
	parent := strings.ToLower(normalized[:idx+1])
	name := normalized[idx+1:]
	if parent == "" {
		parent = "/"
	}
	return parent, name
}

func copyAttrs(src map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{}, len(src))
	for k, v := range src {
		cp[k] = v
	}
	return cp
}
