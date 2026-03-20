package handlers

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/responseray/responseray/internal/models"
)

type UploadHandler struct {
	DB        *pgxpool.Pool
	UploadDir string
}

func (h *UploadHandler) List(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	rows, err := h.DB.Query(r.Context(),
		`SELECT id, site_id, filename, host_name, status, event_count, error_msg, created_at, updated_at
		 FROM uploads WHERE site_id = $1 ORDER BY created_at DESC`, siteID)
	if err != nil {
		httpError(w, err)
		return
	}
	defer rows.Close()

	var uploads []models.Upload
	for rows.Next() {
		var u models.Upload
		if err := rows.Scan(&u.ID, &u.SiteID, &u.Filename, &u.HostName, &u.Status, &u.EventCount, &u.ErrorMsg, &u.CreatedAt, &u.UpdatedAt); err != nil {
			httpError(w, err)
			return
		}
		uploads = append(uploads, u)
	}
	if uploads == nil {
		uploads = []models.Upload{}
	}

	writeJSON(w, uploads)
}

func (h *UploadHandler) Upload(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	r.ParseMultipartForm(5 << 30) // 5 GB max
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	uploadID := uuid.New()
	destDir := filepath.Join(h.UploadDir, uploadID.String())
	if err := os.MkdirAll(destDir, 0755); err != nil {
		httpError(w, fmt.Errorf("create upload dir: %w", err))
		return
	}

	destPath := filepath.Join(destDir, header.Filename)
	dest, err := os.Create(destPath)
	if err != nil {
		httpError(w, fmt.Errorf("create dest file: %w", err))
		return
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		httpError(w, fmt.Errorf("copy file: %w", err))
		return
	}

	upload := models.Upload{
		ID:        uploadID,
		SiteID:    siteID,
		Filename:  header.Filename,
		Status:    "pending",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	_, err = h.DB.Exec(r.Context(),
		`INSERT INTO uploads (id, site_id, filename, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`,
		upload.ID, upload.SiteID, upload.Filename, upload.Status, upload.CreatedAt, upload.UpdatedAt)
	if err != nil {
		httpError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, upload)
}

func (h *UploadHandler) Status(w http.ResponseWriter, r *http.Request) {
	uploadID, err := uuid.Parse(chi.URLParam(r, "uploadID"))
	if err != nil {
		http.Error(w, "invalid upload ID", http.StatusBadRequest)
		return
	}

	var u models.Upload
	err = h.DB.QueryRow(r.Context(),
		`SELECT id, site_id, filename, host_name, status, event_count, error_msg, created_at, updated_at
		 FROM uploads WHERE id = $1`, uploadID).
		Scan(&u.ID, &u.SiteID, &u.Filename, &u.HostName, &u.Status, &u.EventCount, &u.ErrorMsg, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		httpError(w, err)
		return
	}

	writeJSON(w, u)
}

func (h *UploadHandler) Delete(w http.ResponseWriter, r *http.Request) {
	uploadID, err := uuid.Parse(chi.URLParam(r, "uploadID"))
	if err != nil {
		http.Error(w, "invalid upload ID", http.StatusBadRequest)
		return
	}

	_, err = h.DB.Exec(r.Context(), `DELETE FROM uploads WHERE id = $1`, uploadID)
	if err != nil {
		httpError(w, err)
		return
	}

	destDir := filepath.Join(h.UploadDir, uploadID.String())
	os.RemoveAll(destDir)

	w.WriteHeader(http.StatusNoContent)
}
