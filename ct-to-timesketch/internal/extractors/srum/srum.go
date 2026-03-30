package srum

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/go-ese/parser"

	"github.com/NCLGISA/ct-to-timesketch/internal/cache"
	"github.com/NCLGISA/ct-to-timesketch/internal/converter"
	"github.com/NCLGISA/ct-to-timesketch/internal/extractors"
	"github.com/NCLGISA/ct-to-timesketch/internal/progress"
)

var srumTables = map[string]string{
	"application_usage":    "{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}",
	"network_connectivity": "{DD6636C4-8929-4683-974E-22C046A43763}",
	"network_usage":        "{973F5D5C-1D90-4944-BE8E-24B94231A174}",
}

var oleEpoch = time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC)

func init() {
	extractors.Register(&Extractor{})
}

type Extractor struct{}

func (e *Extractor) Name() string        { return "srum" }
func (e *Extractor) Description() string { return "SRUM database (application/network usage history)" }

func (e *Extractor) Extract(cachePath string, conv *converter.Converter, idx *cache.Index) (int, error) {
	files, err := idx.GetCollectedFiles(`^SRUDB\.dat$`, "")
	if err != nil {
		return 0, fmt.Errorf("get SRUM files: %w", err)
	}
	if len(files) == 0 {
		progress.Info("No SRUDB.dat with collected content found")
		return 0, nil
	}

	progress.Info(fmt.Sprintf("Found %d SRUM database(s)", len(files)))
	totalEvents := 0

	for _, f := range files {
		fpath, cleanup := resolveSRUMPath(f)
		if fpath == "" {
			progress.Warning("Failed to resolve SRUDB.dat")
			continue
		}
		if cleanup != nil {
			defer cleanup()
		}

		count := e.parseSRUMPath(fpath, conv)
		totalEvents += count
	}

	progress.Info(fmt.Sprintf("SRUM: %d events extracted", totalEvents))
	return totalEvents, nil
}

func resolveSRUMPath(f cache.CollectedFile) (string, func()) {
	if f.DiskPath != "" {
		return f.DiskPath, nil
	}
	decoded, err := extractors.GetFileContent(f)
	if err != nil || len(decoded) == 0 {
		return "", nil
	}
	tmpPath := filepath.Join(os.TempDir(), "ct_srum_SRUDB.dat")
	if err := os.WriteFile(tmpPath, decoded, 0600); err != nil {
		return "", nil
	}
	return tmpPath, func() { os.Remove(tmpPath) }
}

func (e *Extractor) parseSRUMPath(fpath string, conv *converter.Converter) (result int) {
	defer func() {
		if r := recover(); r != nil {
			progress.Warning(fmt.Sprintf("SRUM parser recovered from panic: %v", r))
			result = 0
		}
	}()
	fd, err := os.Open(fpath)
	if err != nil {
		return 0
	}
	defer fd.Close()

	ctx, err := parser.NewESEContext(fd)
	if err != nil {
		progress.Warning(fmt.Sprintf("Failed to parse ESE database: %v", err))
		return 0
	}

	catalog, err := parser.ReadCatalog(ctx)
	if err != nil {
		progress.Warning(fmt.Sprintf("Failed to read ESE catalog: %v", err))
		return 0
	}

	idMap := buildIDMap(catalog)
	events := 0
	events += parseAppUsage(catalog, conv, idMap)
	events += parseNetConnectivity(catalog, conv, idMap)
	events += parseNetUsage(catalog, conv, idMap)
	return events
}

func buildIDMap(catalog *parser.Catalog) map[int64]string {
	idMap := make(map[int64]string)
	_ = catalog.DumpTable("SruDbIdMapTable", func(row *ordereddict.Dict) (retErr error) {
		defer func() {
			if r := recover(); r != nil {
				retErr = nil
			}
		}()
		idIndex := getRowInt64(row, "IdIndex")
		idBlob := getRowBytes(row, "IdBlob")
		if idIndex == 0 {
			return nil
		}
		if len(idBlob) > 0 {
			resolved := decodeUTF16LE(idBlob)
			if resolved != "" {
				idMap[idIndex] = resolved
			}
		}
		return nil
	})
	return idMap
}

func resolveID(idMap map[int64]string, id int64, context string) string {
	if name, ok := idMap[id]; ok {
		return name
	}
	return fmt.Sprintf("%s-%d", context, id)
}

func parseAppUsage(catalog *parser.Catalog, conv *converter.Converter, idMap map[int64]string) int {
	events := 0
	tableName := srumTables["application_usage"]

	err := catalog.DumpTable(tableName, func(row *ordereddict.Dict) error {
		ts := getRowOLETimestamp(row, "TimeStamp")
		if ts == "" {
			return nil
		}
		appID := getRowInt64(row, "AppId")
		userID := getRowInt64(row, "UserId")
		app := resolveID(idMap, appID, "App")
		user := resolveID(idMap, userID, "User")

		fgTime := getRowInt64(row, "ForegroundCycleTime")
		bgTime := getRowInt64(row, "BackgroundCycleTime")

		msg := fmt.Sprintf("App usage: %s (user: %s, fg: %d, bg: %d)", app, user, fgTime, bgTime)
		if conv.AddEvent(ts, "SRUM Application Usage", msg,
			"srum_app_usage", "CT-SRUM",
			"CyberTriage SRUM - Application Usage",
			"windows:srum:application_usage",
			map[string]interface{}{
				"application":           app,
				"user_sid":              user,
				"foreground_cycle_time": fgTime,
				"background_cycle_time": bgTime,
			}) {
			events++
		}
		return nil
	})
	if err != nil {
		progress.Warning(fmt.Sprintf("SRUM app usage table not found: %v", err))
	}
	return events
}

func parseNetConnectivity(catalog *parser.Catalog, conv *converter.Converter, idMap map[int64]string) int {
	events := 0
	tableName := srumTables["network_connectivity"]

	err := catalog.DumpTable(tableName, func(row *ordereddict.Dict) error {
		ts := getRowOLETimestamp(row, "TimeStamp")
		if ts == "" {
			return nil
		}
		appID := getRowInt64(row, "AppId")
		userID := getRowInt64(row, "UserId")
		app := resolveID(idMap, appID, "Network")
		user := resolveID(idMap, userID, "User")
		connTime := getRowInt64(row, "ConnectedTime")

		msg := fmt.Sprintf("Network connectivity: %s (user: %s, connected: %ds)", app, user, connTime)
		if conv.AddEvent(ts, "SRUM Network Connectivity", msg,
			"srum_network_connectivity", "CT-SRUM",
			"CyberTriage SRUM - Network Connectivity",
			"windows:srum:network_connectivity",
			map[string]interface{}{
				"application":    app,
				"user_sid":       user,
				"connected_time": connTime,
			}) {
			events++
		}
		return nil
	})
	if err != nil {
		progress.Warning(fmt.Sprintf("SRUM network connectivity table not found: %v", err))
	}
	return events
}

func parseNetUsage(catalog *parser.Catalog, conv *converter.Converter, idMap map[int64]string) int {
	events := 0
	tableName := srumTables["network_usage"]

	err := catalog.DumpTable(tableName, func(row *ordereddict.Dict) error {
		ts := getRowOLETimestamp(row, "TimeStamp")
		if ts == "" {
			return nil
		}
		appID := getRowInt64(row, "AppId")
		userID := getRowInt64(row, "UserId")
		app := resolveID(idMap, appID, "App")
		user := resolveID(idMap, userID, "User")
		bytesIn := getRowInt64(row, "BytesRecvd")
		bytesOut := getRowInt64(row, "BytesSent")

		msg := fmt.Sprintf("Network usage: %s (user: %s, recv: %s, sent: %s)",
			app, user, converter.FormatBytes(bytesIn), converter.FormatBytes(bytesOut))
		if conv.AddEvent(ts, "SRUM Network Usage", msg,
			"srum_network_usage", "CT-SRUM",
			"CyberTriage SRUM - Network Usage",
			"windows:srum:network_usage",
			map[string]interface{}{
				"application":    app,
				"user_sid":       user,
				"bytes_received": bytesIn,
				"bytes_sent":     bytesOut,
			}) {
			events++
		}
		return nil
	})
	if err != nil {
		// Not all systems have this table
	}
	return events
}

// --- Row helpers ---

func getRowInt64(row *ordereddict.Dict, key string) int64 {
	val, ok := row.Get(key)
	if !ok || val == nil {
		return 0
	}
	switch v := val.(type) {
	case int64:
		return v
	case uint64:
		return int64(v)
	case int:
		return int64(v)
	case uint32:
		return int64(v)
	case int32:
		return int64(v)
	case float64:
		return int64(v)
	}
	return 0
}

func getRowBytes(row *ordereddict.Dict, key string) []byte {
	val, ok := row.Get(key)
	if !ok || val == nil {
		return nil
	}
	if b, ok := val.([]byte); ok {
		return b
	}
	return nil
}

func getRowOLETimestamp(row *ordereddict.Dict, key string) string {
	val, ok := row.Get(key)
	if !ok || val == nil {
		return ""
	}

	switch v := val.(type) {
	case float64:
		return oleToISO(v)
	case []byte:
		if len(v) >= 8 {
			bits := binary.LittleEndian.Uint64(v)
			f := math.Float64frombits(bits)
			return oleToISO(f)
		}
	case time.Time:
		if v.IsZero() || v.Year() < 1970 || v.Year() > 2100 {
			return ""
		}
		return v.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return ""
}

func oleToISO(oleDate float64) string {
	if oleDate == 0 || math.IsNaN(oleDate) || math.IsInf(oleDate, 0) {
		return ""
	}
	days := time.Duration(oleDate * float64(24*time.Hour))
	t := oleEpoch.Add(days)
	if t.Year() < 1970 || t.Year() > 2100 {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	for len(data) >= 2 && data[len(data)-1] == 0 && data[len(data)-2] == 0 {
		data = data[:len(data)-2]
	}
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	var result []byte
	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch == 0 {
			break
		}
		if ch < 128 {
			result = append(result, byte(ch))
		} else {
			result = append(result, '?')
		}
	}
	return string(result)
}

