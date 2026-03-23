package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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

// Upload handles single-request uploads (kept for backward compat / small files)
func (h *UploadHandler) Upload(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	r.ParseMultipartForm(5 << 30)
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

// InitChunkedUpload creates an upload record in "chunking" status and returns the upload ID.
// POST /api/sites/{siteID}/uploads/init
func (h *UploadHandler) InitChunkedUpload(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Filename   string `json:"filename"`
		TotalSize  int64  `json:"total_size"`
		ChunkSize  int64  `json:"chunk_size"`
		TotalParts int    `json:"total_parts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Filename == "" || req.TotalParts < 1 {
		http.Error(w, "filename, total_size, chunk_size, and total_parts are required", http.StatusBadRequest)
		return
	}

	uploadID := uuid.New()
	chunksDir := filepath.Join(h.UploadDir, uploadID.String(), "chunks")
	if err := os.MkdirAll(chunksDir, 0755); err != nil {
		httpError(w, fmt.Errorf("create chunks dir: %w", err))
		return
	}

	upload := models.Upload{
		ID:        uploadID,
		SiteID:    siteID,
		Filename:  req.Filename,
		Status:    "chunking",
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
	writeJSON(w, map[string]interface{}{
		"upload_id":   uploadID.String(),
		"total_parts": req.TotalParts,
		"chunk_size":  req.ChunkSize,
	})
}

// UploadChunk receives a single chunk.
// PUT /api/sites/{siteID}/uploads/{uploadID}/chunks/{chunkIdx}
func (h *UploadHandler) UploadChunk(w http.ResponseWriter, r *http.Request) {
	uploadID, err := uuid.Parse(chi.URLParam(r, "uploadID"))
	if err != nil {
		http.Error(w, "invalid upload ID", http.StatusBadRequest)
		return
	}

	chunkIdx, err := strconv.Atoi(chi.URLParam(r, "chunkIdx"))
	if err != nil || chunkIdx < 0 {
		http.Error(w, "invalid chunk index", http.StatusBadRequest)
		return
	}

	chunksDir := filepath.Join(h.UploadDir, uploadID.String(), "chunks")
	if _, err := os.Stat(chunksDir); os.IsNotExist(err) {
		http.Error(w, "upload not found or not initialized", http.StatusNotFound)
		return
	}

	chunkPath := filepath.Join(chunksDir, fmt.Sprintf("chunk_%06d", chunkIdx))
	f, err := os.Create(chunkPath)
	if err != nil {
		httpError(w, fmt.Errorf("create chunk file: %w", err))
		return
	}
	defer f.Close()

	written, err := io.Copy(f, r.Body)
	if err != nil {
		os.Remove(chunkPath)
		httpError(w, fmt.Errorf("write chunk: %w", err))
		return
	}

	writeJSON(w, map[string]interface{}{
		"chunk_idx": chunkIdx,
		"size":      written,
	})
}

// CompleteChunkedUpload reassembles chunks into the final file and marks the upload as pending.
// POST /api/sites/{siteID}/uploads/{uploadID}/complete
func (h *UploadHandler) CompleteChunkedUpload(w http.ResponseWriter, r *http.Request) {
	uploadID, err := uuid.Parse(chi.URLParam(r, "uploadID"))
	if err != nil {
		http.Error(w, "invalid upload ID", http.StatusBadRequest)
		return
	}

	var status string
	var filename string
	err = h.DB.QueryRow(r.Context(),
		`SELECT status, filename FROM uploads WHERE id = $1`, uploadID).Scan(&status, &filename)
	if err != nil {
		httpError(w, err)
		return
	}
	if status != "chunking" {
		http.Error(w, "upload is not in chunking state", http.StatusBadRequest)
		return
	}

	chunksDir := filepath.Join(h.UploadDir, uploadID.String(), "chunks")
	entries, err := os.ReadDir(chunksDir)
	if err != nil {
		httpError(w, fmt.Errorf("read chunks dir: %w", err))
		return
	}

	var chunkFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), "chunk_") {
			chunkFiles = append(chunkFiles, filepath.Join(chunksDir, e.Name()))
		}
	}
	sort.Strings(chunkFiles)

	if len(chunkFiles) == 0 {
		http.Error(w, "no chunks found", http.StatusBadRequest)
		return
	}

	destPath := filepath.Join(h.UploadDir, uploadID.String(), filename)
	dest, err := os.Create(destPath)
	if err != nil {
		httpError(w, fmt.Errorf("create dest file: %w", err))
		return
	}

	var totalSize int64
	for _, cp := range chunkFiles {
		cf, err := os.Open(cp)
		if err != nil {
			dest.Close()
			httpError(w, fmt.Errorf("open chunk %s: %w", cp, err))
			return
		}
		n, err := io.Copy(dest, cf)
		cf.Close()
		if err != nil {
			dest.Close()
			httpError(w, fmt.Errorf("copy chunk: %w", err))
			return
		}
		totalSize += n
	}
	dest.Close()

	os.RemoveAll(chunksDir)

	_, err = h.DB.Exec(r.Context(),
		`UPDATE uploads SET status = 'pending', updated_at = NOW() WHERE id = $1`, uploadID)
	if err != nil {
		httpError(w, err)
		return
	}

	writeJSON(w, map[string]interface{}{
		"upload_id":  uploadID.String(),
		"filename":   filename,
		"total_size": totalSize,
		"status":     "pending",
	})
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
