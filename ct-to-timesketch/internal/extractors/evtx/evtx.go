package evtx

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	goevtx "www.velocidex.com/golang/evtx"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

const windowsEpochDelta = 116444736000000000 // 100-ns intervals between 1601-01-01 and 1970-01-01

func init() {
	extractors.Register(&Extractor{})
}

type Extractor struct{}

func (e *Extractor) Name() string        { return "evtx" }
func (e *Extractor) Description() string { return "Windows Event Log files (.evtx) via pure-Go parser" }

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	evtxFiles, err := idx.GetCollectedFiles(`\.evtx$`, "")
	if err != nil {
		return 0, fmt.Errorf("get EVTX files: %w", err)
	}
	if len(evtxFiles) == 0 {
		progress.Warning("No .evtx files with collected content found")
		return 0, nil
	}

	progress.Info(fmt.Sprintf("Processing %d EVTX files with pure-Go parser", len(evtxFiles)))

	totalEvents := 0
	for i, ef := range evtxFiles {
		progress.ProgressLine("EVTX [%d/%d] %s", i+1, len(evtxFiles), ef.Filename)

		fpath, cleanup := resolveFilePath(ef)
		if fpath == "" {
			progress.Warning(fmt.Sprintf("Failed to resolve %s", ef.Filename))
			continue
		}
		if cleanup != nil {
			defer cleanup()
		}

		count, err := e.parseEVTXPath(fpath, ef.Filename, conv)
		if err != nil {
			progress.Warning(fmt.Sprintf("Failed to parse %s: %v", ef.Filename, err))
			continue
		}
		totalEvents += count
	}

	progress.ProgressDone()
	progress.Info(fmt.Sprintf("EVTX: %d events extracted", totalEvents))
	return totalEvents, nil
}

// resolveFilePath returns a local file path for the collected file.
// If DiskPath is set (artifact mode), returns it directly.
// Otherwise decodes content and writes a temp file, returning a cleanup func.
func resolveFilePath(ef cache.CollectedFile) (string, func()) {
	if ef.DiskPath != "" {
		return ef.DiskPath, nil
	}
	decoded, err := extractors.GetFileContent(ef)
	if err != nil || len(decoded) == 0 {
		return "", nil
	}
	safe := regexp.MustCompile(`[^\w\-_.]`).ReplaceAllString(ef.Filename, "_")
	tmpPath := filepath.Join(os.TempDir(), "ct_evtx_"+safe)
	if err := os.WriteFile(tmpPath, decoded, 0600); err != nil {
		return "", nil
	}
	return tmpPath, func() { os.Remove(tmpPath) }
}

func (e *Extractor) parseEVTXPath(fpath, filename string, conv *converter.Converter) (int, error) {
	fd, err := os.Open(fpath)
	if err != nil {
		return 0, fmt.Errorf("open: %w", err)
	}
	defer fd.Close()

	info, err := fd.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat: %w", err)
	}
	fileSize := info.Size()

	var header goevtx.EVTXHeader
	if err := binary.Read(fd, binary.LittleEndian, &header); err != nil {
		return 0, fmt.Errorf("read EVTX header: %w", err)
	}

	if string(header.Magic[:]) != "ElfFile\x00" {
		return 0, fmt.Errorf("invalid EVTX magic in %s", filename)
	}

	channel := inferChannelFromFilename(filename)
	count := 0
	offset := int64(0x1000)
	numChunks := (fileSize - 0x1000) / 0x10000
	if numChunks <= 0 {
		numChunks = 1
	}

	for i := int64(0); i < numChunks; i++ {
		chunk, err := goevtx.NewChunk(fd, offset)
		if err != nil {
			offset += 0x10000
			continue
		}
		if string(chunk.Header.Magic[:]) != "ElfChnk\x00" {
			offset += 0x10000
			continue
		}

		records, err := chunk.Parse(0)
		if err != nil {
			offset += 0x10000
			continue
		}

		for _, rec := range records {
			if e.convertRecord(rec, channel, filename, conv) {
				count++
			}
		}

		offset += 0x10000
	}

	return count, nil
}

func (e *Extractor) convertRecord(rec *goevtx.EventRecord, defaultChannel, filename string, conv *converter.Converter) bool {
	ts := filetimeToISO(rec.Header.FileTime)
	if ts == "" {
		return false
	}

	eventDict := rec.Event
	eventNode := dictGet(eventDict, "Event")
	if eventNode == nil {
		eventNode = eventDict
	}

	system := dictGet(eventNode, "System")
	eventData := dictGet(eventNode, "EventData")
	userData := dictGet(eventNode, "UserData")

	eid := extractEventID(dictGet(system, "EventID"))
	if eid == 0 {
		return false
	}

	channel := dictStr(system, "Channel")
	if channel == "" {
		channel = defaultChannel
	}

	computer := dictStr(system, "Computer")
	if computer == "" {
		computer = conv.Hostname
	}

	providerName := extractProviderName(dictGet(system, "Provider"))
	userSID := extractUserSID(dictGet(system, "Security"))

	fields := extractEventDataFields(eventData)
	mergeUserData(fields, userData)

	payload := make(map[string]interface{}, len(fields))
	for k, v := range fields {
		payload[k] = v
	}

	message := converter.BuildWindowsEventMessage(eid, channel, payload)
	eventType := converter.CategorizeWindowsEvent(eid, channel)

	attrs := map[string]interface{}{
		"source_name":      providerName,
		"channel":          channel,
		"event_identifier": strconv.Itoa(eid),
		"computer_name":    computer,
		"record_number":    strconv.FormatUint(rec.Header.RecordID, 10),
		"user_sid":         userSID,
	}

	i := 0
	for k, v := range fields {
		if i >= 20 {
			break
		}
		attrs[k] = v
		i++
	}

	return conv.AddEvent(
		ts,
		"Event Log Entry",
		message,
		eventType,
		"CT-EVTX",
		"CyberTriage EVTX - "+channel,
		"windows:evtx:record",
		attrs,
	)
}

// --- ordereddict helpers ---

func dictGet(v interface{}, key string) interface{} {
	if v == nil {
		return nil
	}
	if d, ok := v.(*ordereddict.Dict); ok {
		val, _ := d.Get(key)
		return val
	}
	return nil
}

func dictStr(v interface{}, key string) string {
	val := dictGet(v, key)
	if val == nil {
		return ""
	}
	return fmt.Sprint(val)
}

func dictKeys(v interface{}) []string {
	if d, ok := v.(*ordereddict.Dict); ok {
		return d.Keys()
	}
	return nil
}

func extractEventID(v interface{}) int {
	if v == nil {
		return 0
	}
	switch t := v.(type) {
	case *ordereddict.Dict:
		for _, key := range []string{"Value", "#text", ""} {
			if val, pres := t.Get(key); pres && val != nil {
				return toInt(val)
			}
		}
		for _, k := range t.Keys() {
			if val, pres := t.Get(k); pres && val != nil {
				n := toInt(val)
				if n > 0 {
					return n
				}
			}
		}
		return 0
	default:
		return toInt(v)
	}
}

func toInt(v interface{}) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case float32:
		return int(t)
	case int64:
		return int(t)
	case int:
		return t
	case uint64:
		return int(t)
	case uint32:
		return int(t)
	case uint16:
		return int(t)
	case string:
		n, _ := strconv.Atoi(t)
		return n
	}
	return 0
}

func extractProviderName(v interface{}) string {
	if v == nil {
		return "Unknown"
	}
	if d, ok := v.(*ordereddict.Dict); ok {
		for _, key := range []string{"Name", "@Name"} {
			if val, pres := d.Get(key); pres && val != nil {
				s := fmt.Sprint(val)
				if s != "" {
					return s
				}
			}
		}
		if attrs := dictGet(v, "#attributes"); attrs != nil {
			if name := dictStr(attrs, "Name"); name != "" {
				return name
			}
		}
	}
	s := fmt.Sprint(v)
	if s != "" && s != "<nil>" && s != "map[]" {
		return s
	}
	return "Unknown"
}

func extractUserSID(v interface{}) string {
	if v == nil {
		return ""
	}
	if d, ok := v.(*ordereddict.Dict); ok {
		for _, key := range []string{"UserID", "@UserID"} {
			if val, pres := d.Get(key); pres && val != nil {
				return fmt.Sprint(val)
			}
		}
		if attrs := dictGet(v, "#attributes"); attrs != nil {
			if sid := dictStr(attrs, "UserID"); sid != "" {
				return sid
			}
		}
	}
	return ""
}

func extractEventDataFields(eventData interface{}) map[string]string {
	fields := make(map[string]string)
	if eventData == nil {
		return fields
	}

	d, ok := eventData.(*ordereddict.Dict)
	if !ok {
		return fields
	}

	for _, key := range d.Keys() {
		if strings.HasPrefix(key, "#") || strings.HasPrefix(key, "@") || key == "xmlns" {
			continue
		}

		val, _ := d.Get(key)
		if val == nil {
			continue
		}

		if key == "Data" {
			extractDataArray(val, fields)
			continue
		}

		switch v := val.(type) {
		case *ordereddict.Dict:
			flattenDict("", v, fields)
		default:
			fields[key] = fmt.Sprint(v)
		}
	}

	return fields
}

func extractDataArray(val interface{}, fields map[string]string) {
	switch items := val.(type) {
	case []interface{}:
		for _, item := range items {
			if d, ok := item.(*ordereddict.Dict); ok {
				name := dictStr(d, "@Name")
				if name == "" {
					name = dictStr(d, "Name")
				}
				text := dictStr(d, "#text")
				if text == "" {
					text = dictStr(d, "Value")
					if text == "" {
						text = dictStr(d, "")
					}
				}
				if name != "" {
					fields[name] = text
				}
			}
		}
	case *ordereddict.Dict:
		name := dictStr(items, "@Name")
		if name == "" {
			name = dictStr(items, "Name")
		}
		text := dictStr(items, "#text")
		if text == "" {
			text = dictStr(items, "Value")
		}
		if name != "" {
			fields[name] = text
		}
	}
}

func flattenDict(prefix string, d *ordereddict.Dict, fields map[string]string) {
	for _, key := range d.Keys() {
		if strings.HasPrefix(key, "#") || strings.HasPrefix(key, "@") || key == "xmlns" {
			continue
		}
		val, _ := d.Get(key)
		if val == nil {
			continue
		}
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "_" + key
		}
		switch v := val.(type) {
		case *ordereddict.Dict:
			flattenDict(fullKey, v, fields)
		default:
			fields[fullKey] = fmt.Sprint(v)
		}
	}
}

func mergeUserData(fields map[string]string, userData interface{}) {
	if userData == nil {
		return
	}
	d, ok := userData.(*ordereddict.Dict)
	if !ok {
		return
	}

	for _, key := range d.Keys() {
		if strings.HasPrefix(key, "#") || strings.HasPrefix(key, "@") || key == "xmlns" {
			continue
		}
		val, _ := d.Get(key)
		if val == nil {
			continue
		}

		if inner, ok := val.(*ordereddict.Dict); ok {
			for _, innerKey := range inner.Keys() {
				if strings.HasPrefix(innerKey, "#") || strings.HasPrefix(innerKey, "@") || innerKey == "xmlns" {
					continue
				}
				innerVal, _ := inner.Get(innerKey)
				if innerVal == nil {
					continue
				}
				if _, exists := fields[innerKey]; !exists {
					fields[innerKey] = fmt.Sprint(innerVal)
				}
			}
		}
	}
}

func filetimeToISO(ft uint64) string {
	if ft == 0 || ft < windowsEpochDelta {
		return ""
	}
	ns := int64(ft-windowsEpochDelta) * 100
	t := time.Unix(0, ns).UTC()
	if t.Year() < 1970 || t.Year() > 2100 {
		return ""
	}
	return t.Format("2006-01-02T15:04:05.000Z")
}

func inferChannelFromFilename(filename string) string {
	name := strings.TrimSuffix(filename, ".evtx")
	name = strings.TrimSuffix(name, ".EVTX")

	replacer := strings.NewReplacer(
		"%4", "/",
		"%25", "%",
	)
	name = replacer.Replace(name)

	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	if idx := strings.LastIndex(name, "\\"); idx >= 0 {
		name = name[idx+1:]
	}

	return name
}

