package handlers

import (
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

	h.DB.QueryRow(ctx, `SELECT COUNT(*) FROM events WHERE site_id = $1`, siteID).Scan(&stats.TotalEvents)
	h.DB.QueryRow(ctx, `SELECT COUNT(*) FROM events WHERE site_id = $1 AND ct_significance = 'LikelyNotable'`, siteID).Scan(&stats.NotableCount)
	h.DB.QueryRow(ctx, `SELECT COUNT(*) FROM events WHERE site_id = $1 AND is_suspicious = TRUE`, siteID).Scan(&stats.SuspiciousCount)

	rows, err := h.DB.Query(ctx, `SELECT event_type, COUNT(*) FROM events WHERE site_id = $1 GROUP BY event_type ORDER BY COUNT(*) DESC`, siteID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var et string
			var cnt int64
			rows.Scan(&et, &cnt)
			stats.EventCounts[et] = cnt
		}
	}

	frows, err := h.DB.Query(ctx, `SELECT finding, COUNT(*) FROM events WHERE site_id = $1 AND finding IS NOT NULL GROUP BY finding`, siteID)
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
