package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

type Site struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Upload struct {
	ID         uuid.UUID `json:"id"`
	SiteID     uuid.UUID `json:"site_id"`
	Filename   string    `json:"filename"`
	HostName   string    `json:"host_name"`
	Status     string    `json:"status"`
	EventCount int64     `json:"event_count"`
	ErrorMsg   string    `json:"error_msg,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	ProgressStage    string `json:"progress_stage,omitempty"`
	ProgressPercent  int    `json:"progress_percent,omitempty"`
	EventsProcessed  int64  `json:"events_processed,omitempty"`
	EventsTotal      int64  `json:"events_total,omitempty"`
	QueuePosition    int64  `json:"queue_position,omitempty"`
	QueueLength      int64  `json:"queue_length,omitempty"`
	ProcessingStart  string `json:"processing_started_at,omitempty"`
}

type Event struct {
	ID              int64           `json:"id"`
	UploadID        uuid.UUID       `json:"upload_id"`
	SiteID          uuid.UUID       `json:"site_id"`
	DateTime        time.Time       `json:"datetime"`
	EventType       string          `json:"event_type"`
	DataType        *string         `json:"data_type,omitempty"`
	Message         *string         `json:"message,omitempty"`
	HostName        *string         `json:"host_name,omitempty"`
	SourceShort     *string         `json:"source_short,omitempty"`
	TimestampDesc   *string         `json:"timestamp_desc,omitempty"`
	CTSignificance  *string         `json:"ct_significance,omitempty"`
	IsSuspicious    bool            `json:"is_suspicious"`
	Finding         *string         `json:"finding,omitempty"`
	FindingNote     *string         `json:"finding_note,omitempty"`
	Data            json.RawMessage `json:"data"`
}

type FindingUpdate struct {
	Finding     *string `json:"finding"`
	FindingNote *string `json:"finding_note"`
}

type EventQuery struct {
	SiteID     uuid.UUID  `json:"site_id"`
	UploadID   *uuid.UUID `json:"upload_id,omitempty"`
	EventTypes []string   `json:"event_types,omitempty"`
	Search     string    `json:"search,omitempty"`
	Finding    string    `json:"finding,omitempty"`
	SortField  string    `json:"sort_field,omitempty"`
	SortDir    string    `json:"sort_dir,omitempty"`
	Offset     int       `json:"offset"`
	Limit      int       `json:"limit"`

	// Filters on JSONB data
	DataFilters map[string]string `json:"data_filters,omitempty"`
	Channel     string            `json:"channel,omitempty"`

	DateFrom string `json:"date_from,omitempty"`
	DateTo   string `json:"date_to,omitempty"`

	OnlyNotable    bool `json:"only_notable,omitempty"`
	OnlySuspicious bool `json:"only_suspicious,omitempty"`

	LuceneQuery string `json:"q,omitempty"`
}

type PagedResult struct {
	Items      interface{} `json:"items"`
	Total      int64       `json:"total"`
	Offset     int         `json:"offset"`
	Limit      int         `json:"limit"`
	HasMore    bool        `json:"has_more"`
}

type DashboardStats struct {
	TotalEvents    int64            `json:"total_events"`
	EventCounts    map[string]int64 `json:"event_counts"`
	NotableCount   int64            `json:"notable_count"`
	SuspiciousCount int64           `json:"suspicious_count"`
	FindingCounts  map[string]int64 `json:"finding_counts"`
	Uploads        []Upload         `json:"uploads"`
}
