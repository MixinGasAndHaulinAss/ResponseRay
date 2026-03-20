package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/responseray/responseray/internal/models"
)

type SiteHandler struct {
	DB *pgxpool.Pool
}

func (h *SiteHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(r.Context(),
		`SELECT s.id, s.name, s.description, s.created_at, s.updated_at,
		        COALESCE(uc.upload_count, 0), COALESCE(ec.event_count, 0)
		 FROM sites s
		 LEFT JOIN (SELECT site_id, COUNT(*) as upload_count FROM uploads GROUP BY site_id) uc ON uc.site_id = s.id
		 LEFT JOIN (SELECT site_id, COUNT(*) as event_count FROM events GROUP BY site_id) ec ON ec.site_id = s.id
		 ORDER BY s.updated_at DESC`)
	if err != nil {
		httpError(w, err)
		return
	}
	defer rows.Close()

	type siteWithCounts struct {
		models.Site
		UploadCount int64 `json:"upload_count"`
		EventCount  int64 `json:"event_count"`
	}

	var sites []siteWithCounts
	for rows.Next() {
		var s siteWithCounts
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.CreatedAt, &s.UpdatedAt, &s.UploadCount, &s.EventCount); err != nil {
			httpError(w, err)
			return
		}
		sites = append(sites, s)
	}
	if sites == nil {
		sites = []siteWithCounts{}
	}

	writeJSON(w, sites)
}

func (h *SiteHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	site := models.Site{
		ID:          uuid.New(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	_, err := h.DB.Exec(r.Context(),
		`INSERT INTO sites (id, name, description, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`,
		site.ID, site.Name, site.Description, site.CreatedAt, site.UpdatedAt)
	if err != nil {
		httpError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, site)
}

func (h *SiteHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	var site models.Site
	err = h.DB.QueryRow(r.Context(),
		`SELECT id, name, description, created_at, updated_at FROM sites WHERE id = $1`, id).
		Scan(&site.ID, &site.Name, &site.Description, &site.CreatedAt, &site.UpdatedAt)
	if err != nil {
		httpError(w, err)
		return
	}

	writeJSON(w, site)
}

func (h *SiteHandler) Update(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	_, err = h.DB.Exec(r.Context(),
		`UPDATE sites SET name = $2, description = $3, updated_at = NOW() WHERE id = $1`,
		id, req.Name, req.Description)
	if err != nil {
		httpError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *SiteHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	_, err = h.DB.Exec(r.Context(), `DELETE FROM sites WHERE id = $1`, id)
	if err != nil {
		httpError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
