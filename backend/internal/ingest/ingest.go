package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const batchSize = 5000

type Ingester struct {
	DB *pgxpool.Pool
}

type rawEvent struct {
	DateTime       string          `json:"datetime"`
	EventType      string          `json:"event_type"`
	DataType       string          `json:"data_type"`
	Message        string          `json:"message"`
	HostName       string          `json:"host_name"`
	SourceShort    string          `json:"source_short"`
	TimestampDesc  string          `json:"timestamp_desc"`
	CTSignificance string          `json:"ct_significance"`
	IsSuspicious   interface{}     `json:"is_suspicious"`
	Raw            json.RawMessage `json:"-"`
}

type eventRow struct {
	UploadID       uuid.UUID
	SiteID         uuid.UUID
	DateTime       time.Time
	EventType      string
	DataType       *string
	Message        *string
	HostName       *string
	SourceShort    *string
	TimestampDesc  *string
	CTSignificance *string
	IsSuspicious   bool
	Data           json.RawMessage
}

type ProgressFunc func(processed, total int64)

func CountLines(filePath string) (int64, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	var count int64
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		if len(scanner.Bytes()) > 0 {
			count++
		}
	}
	return count, scanner.Err()
}

func (ing *Ingester) IngestJSONL(ctx context.Context, filePath string, uploadID, siteID uuid.UUID, onProgress ProgressFunc) (int64, string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return 0, "", fmt.Errorf("open jsonl: %w", err)
	}
	defer f.Close()

	var hostName string
	var totalInserted int64
	batch := make([]eventRow, 0, batchSize)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 4*1024*1024), 4*1024*1024) // 4MB line buffer

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)
		lineCopy = sanitizeJSON(lineCopy)

		var raw rawEvent
		if err := json.Unmarshal(lineCopy, &raw); err != nil {
			log.Printf("skip malformed line: %v", err)
			continue
		}

		dt, err := parseDateTime(raw.DateTime)
		if err != nil {
			dt = time.Now()
		}

		if hostName == "" && raw.HostName != "" {
			hostName = raw.HostName
		}

		row := eventRow{
			UploadID:     uploadID,
			SiteID:       siteID,
			DateTime:     dt,
			EventType:    raw.EventType,
			IsSuspicious: parseBool(raw.IsSuspicious),
			Data:         json.RawMessage(lineCopy),
		}

		if raw.DataType != "" {
			row.DataType = &raw.DataType
		}
		if raw.Message != "" {
			row.Message = &raw.Message
		}
		if raw.HostName != "" {
			row.HostName = &raw.HostName
		}
		if raw.SourceShort != "" {
			row.SourceShort = &raw.SourceShort
		}
		if raw.TimestampDesc != "" {
			row.TimestampDesc = &raw.TimestampDesc
		}
		if raw.CTSignificance != "" {
			row.CTSignificance = &raw.CTSignificance
		}

		batch = append(batch, row)
		if len(batch) >= batchSize {
			n, err := ing.insertBatch(ctx, batch)
			if err != nil {
				return totalInserted, hostName, fmt.Errorf("insert batch at %d: %w", totalInserted, err)
			}
			totalInserted += n
			batch = batch[:0]

			if onProgress != nil {
				onProgress(totalInserted, 0)
			}
			if totalInserted%100000 == 0 {
				log.Printf("Ingested %d events...", totalInserted)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return totalInserted, hostName, fmt.Errorf("scanner: %w", err)
	}

	if len(batch) > 0 {
		n, err := ing.insertBatch(ctx, batch)
		if err != nil {
			return totalInserted, hostName, fmt.Errorf("insert final batch: %w", err)
		}
		totalInserted += n
	}

	return totalInserted, hostName, nil
}

func (ing *Ingester) insertBatch(ctx context.Context, rows []eventRow) (int64, error) {
	columns := []string{
		"upload_id", "site_id", "datetime", "event_type", "data_type",
		"message", "host_name", "source_short", "timestamp_desc",
		"ct_significance", "is_suspicious", "data",
	}

	copyRows := make([][]interface{}, len(rows))
	for i, r := range rows {
		copyRows[i] = []interface{}{
			r.UploadID, r.SiteID, r.DateTime, r.EventType, r.DataType,
			r.Message, r.HostName, r.SourceShort, r.TimestampDesc,
			r.CTSignificance, r.IsSuspicious, r.Data,
		}
	}

	n, err := ing.DB.CopyFrom(ctx,
		pgx.Identifier{"events"},
		columns,
		pgx.CopyFromRows(copyRows),
	)
	return n, err
}

func parseDateTime(s string) (time.Time, error) {
	formats := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse datetime: %s", s)
}

func sanitizeJSON(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte(`\u0000`), []byte{})
	data = bytes.ReplaceAll(data, []byte(`\u0001`), []byte{})
	data = bytes.ReplaceAll(data, []byte(`\u0002`), []byte{})
	data = bytes.ReplaceAll(data, []byte(`\u0003`), []byte{})
	data = bytes.ReplaceAll(data, []byte(`\u0004`), []byte{})
	data = bytes.ReplaceAll(data, []byte(`\u0005`), []byte{})
	data = bytes.ReplaceAll(data, []byte(`\u0006`), []byte{})
	data = bytes.ReplaceAll(data, []byte(`\u0007`), []byte{})
	data = bytes.ReplaceAll(data, []byte(`\u0008`), []byte{})
	return data
}

func parseBool(v interface{}) bool {
	if v == nil {
		return false
	}
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return strings.EqualFold(val, "true")
	default:
		return false
	}
}
