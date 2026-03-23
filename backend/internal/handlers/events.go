package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/responseray/responseray/internal/models"
)

type EventHandler struct {
	DB *pgxpool.Pool
}

func (h *EventHandler) Query(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	q := models.EventQuery{
		SiteID:    siteID,
		Offset:    queryInt(r, "offset", 0),
		Limit:     queryInt(r, "limit", 100),
		SortField: r.URL.Query().Get("sort"),
		SortDir:   r.URL.Query().Get("dir"),
		Search:    r.URL.Query().Get("search"),
		Finding:   r.URL.Query().Get("finding"),
		Channel:   r.URL.Query().Get("channel"),
		DateFrom:  r.URL.Query().Get("date_from"),
		DateTo:    r.URL.Query().Get("date_to"),
	}

	if q.Limit > 1000 {
		q.Limit = 1000
	}

	if types := r.URL.Query().Get("event_types"); types != "" {
		q.EventTypes = strings.Split(types, ",")
	}

	if r.URL.Query().Get("notable") == "true" {
		q.OnlyNotable = true
	}
	if r.URL.Query().Get("suspicious") == "true" {
		q.OnlySuspicious = true
	}

	// Parse data filters from query params prefixed with "data."
	q.DataFilters = make(map[string]string)
	for key, vals := range r.URL.Query() {
		if strings.HasPrefix(key, "data.") && len(vals) > 0 {
			q.DataFilters[strings.TrimPrefix(key, "data.")] = vals[0]
		}
	}

	events, total, err := h.queryEvents(r, q)
	if err != nil {
		httpError(w, err)
		return
	}

	writeJSON(w, models.PagedResult{
		Items:   events,
		Total:   total,
		Offset:  q.Offset,
		Limit:   q.Limit,
		HasMore: int64(q.Offset+q.Limit) < total,
	})
}

func (h *EventHandler) queryEvents(r *http.Request, q models.EventQuery) ([]models.Event, int64, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	conditions = append(conditions, fmt.Sprintf("site_id = $%d", argIdx))
	args = append(args, q.SiteID)
	argIdx++

	if len(q.EventTypes) > 0 {
		placeholders := make([]string, len(q.EventTypes))
		for i, et := range q.EventTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, et)
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("event_type IN (%s)", strings.Join(placeholders, ",")))
	}

	if q.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(to_tsvector('english', COALESCE(message, '')) @@ plainto_tsquery('english', $%d) OR message ILIKE $%d)",
			argIdx, argIdx+1))
		args = append(args, q.Search, "%"+q.Search+"%")
		argIdx += 2
	}

	if q.Finding != "" {
		switch q.Finding {
		case "none":
			conditions = append(conditions, "finding IS NULL")
		case "any":
			conditions = append(conditions, "finding IS NOT NULL")
		default:
			conditions = append(conditions, fmt.Sprintf("finding = $%d", argIdx))
			args = append(args, q.Finding)
			argIdx++
		}
	}

	if q.OnlyNotable {
		conditions = append(conditions, "ct_significance = 'LikelyNotable'")
	}
	if q.OnlySuspicious {
		conditions = append(conditions, "is_suspicious = TRUE")
	}

	if q.DateFrom != "" {
		conditions = append(conditions, fmt.Sprintf("datetime >= $%d", argIdx))
		args = append(args, q.DateFrom)
		argIdx++
	}
	if q.DateTo != "" {
		conditions = append(conditions, fmt.Sprintf("datetime <= $%d", argIdx))
		args = append(args, q.DateTo)
		argIdx++
	}

	if q.Channel != "" {
		conditions = append(conditions, fmt.Sprintf("data->>'channel' = $%d", argIdx))
		args = append(args, q.Channel)
		argIdx++
	}

	for key, val := range q.DataFilters {
		conditions = append(conditions, fmt.Sprintf("data->>%s = $%d", quoteIdent(key), argIdx))
		args = append(args, val)
		argIdx++
	}

	where := strings.Join(conditions, " AND ")

	var total int64
	countSQL := fmt.Sprintf("SELECT COUNT(*) FROM events WHERE %s", where)
	if err := h.DB.QueryRow(r.Context(), countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy := "datetime DESC"
	allowedSorts := map[string]bool{"datetime": true, "event_type": true, "message": true, "id": true}
	if q.SortField != "" && allowedSorts[q.SortField] {
		dir := "ASC"
		if strings.EqualFold(q.SortDir, "desc") {
			dir = "DESC"
		}
		orderBy = fmt.Sprintf("%s %s", q.SortField, dir)
	}

	dataSQL := fmt.Sprintf(
		`SELECT id, upload_id, site_id, datetime, event_type, data_type, message, host_name,
		        source_short, timestamp_desc, ct_significance, is_suspicious, finding, finding_note, data
		 FROM events WHERE %s ORDER BY %s LIMIT $%d OFFSET $%d`,
		where, orderBy, argIdx, argIdx+1)
	args = append(args, q.Limit, q.Offset)

	rows, err := h.DB.Query(r.Context(), dataSQL, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var events []models.Event
	for rows.Next() {
		var e models.Event
		if err := rows.Scan(&e.ID, &e.UploadID, &e.SiteID, &e.DateTime, &e.EventType,
			&e.DataType, &e.Message, &e.HostName, &e.SourceShort, &e.TimestampDesc,
			&e.CTSignificance, &e.IsSuspicious, &e.Finding, &e.FindingNote, &e.Data); err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}
	if events == nil {
		events = []models.Event{}
	}

	return events, total, nil
}

func (h *EventHandler) UpdateFinding(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	eventIDStr := chi.URLParam(r, "eventID")
	var eventID int64
	fmt.Sscanf(eventIDStr, "%d", &eventID)
	if eventID == 0 {
		http.Error(w, "invalid event ID", http.StatusBadRequest)
		return
	}

	var req models.FindingUpdate
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	_, err = h.DB.Exec(r.Context(),
		`UPDATE events SET finding = $3, finding_note = $4 WHERE id = $1 AND site_id = $2`,
		eventID, siteID, req.Finding, req.FindingNote)
	if err != nil {
		httpError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *EventHandler) BulkUpdateFinding(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	var req struct {
		EventIDs    []int64 `json:"event_ids"`
		Finding     *string `json:"finding"`
		FindingNote *string `json:"finding_note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.EventIDs) == 0 {
		http.Error(w, "event_ids required", http.StatusBadRequest)
		return
	}

	_, err = h.DB.Exec(r.Context(),
		`UPDATE events SET finding = $3, finding_note = $4 WHERE id = ANY($1) AND site_id = $2`,
		req.EventIDs, siteID, req.Finding, req.FindingNote)
	if err != nil {
		httpError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func quoteIdent(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
