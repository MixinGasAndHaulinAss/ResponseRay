package handlers

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/responseray/responseray/internal/models"
)

type DashboardHandler struct {
	DB *pgxpool.Pool
}

func (h *DashboardHandler) Stats(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	stats := models.DashboardStats{
		EventCounts:   make(map[string]int64),
		FindingCounts: make(map[string]int64),
	}

	where := "site_id = $1"
	args := []interface{}{siteID}
	if uid := r.URL.Query().Get("upload_id"); uid != "" {
		parsed, parseErr := uuid.Parse(uid)
		if parseErr != nil {
			http.Error(w, "invalid upload_id", http.StatusBadRequest)
			return
		}
		where += " AND upload_id = $2"
		args = append(args, parsed)
	}

	h.DB.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE %s`, where), args...).Scan(&stats.TotalEvents)
	h.DB.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE %s AND ct_significance = 'LikelyNotable'`, where), args...).Scan(&stats.NotableCount)
	h.DB.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE %s AND is_suspicious = TRUE`, where), args...).Scan(&stats.SuspiciousCount)

	rows, err := h.DB.Query(ctx, fmt.Sprintf(`SELECT event_type, COUNT(*) FROM events WHERE %s GROUP BY event_type ORDER BY COUNT(*) DESC`, where), args...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var et string
			var cnt int64
			rows.Scan(&et, &cnt)
			stats.EventCounts[et] = cnt
		}
	}

	frows, err := h.DB.Query(ctx, fmt.Sprintf(`SELECT finding, COUNT(*) FROM events WHERE %s AND finding IS NOT NULL GROUP BY finding`, where), args...)
	if err == nil {
		defer frows.Close()
		for frows.Next() {
			var f string
			var cnt int64
			frows.Scan(&f, &cnt)
			stats.FindingCounts[f] = cnt
		}
	}

	urows, err := h.DB.Query(ctx,
		`SELECT id, site_id, filename, host_name, status, event_count, error_msg, created_at, updated_at
		 FROM uploads WHERE site_id = $1 ORDER BY created_at DESC`, siteID)
	if err == nil {
		defer urows.Close()
		for urows.Next() {
			var u models.Upload
			urows.Scan(&u.ID, &u.SiteID, &u.Filename, &u.HostName, &u.Status, &u.EventCount, &u.ErrorMsg, &u.CreatedAt, &u.UpdatedAt)
			stats.Uploads = append(stats.Uploads, u)
		}
	}
	if stats.Uploads == nil {
		stats.Uploads = []models.Upload{}
	}

	writeJSON(w, stats)
}
