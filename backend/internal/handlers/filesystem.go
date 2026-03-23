package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)


type FilesystemHandler struct {
	DB *pgxpool.Pool
}

type fsEntry struct {
	Name        string  `json:"name"`
	IsDir       bool    `json:"is_dir"`
	Size        *int64  `json:"size,omitempty"`
	FileCount   int     `json:"file_count,omitempty"`
	LatestTime  *string `json:"latest_time,omitempty"`
	MD5         *string `json:"md5,omitempty"`
	SHA256      *string `json:"sha256,omitempty"`
	IsDeleted   bool    `json:"is_deleted,omitempty"`
	HasTimestomp bool   `json:"has_timestomp,omitempty"`
	Significance *string `json:"significance,omitempty"`
	IsSuspicious bool    `json:"is_suspicious,omitempty"`
}

type fsResponse struct {
	Path    string    `json:"path"`
	Entries []fsEntry `json:"entries"`
}

func (h *FilesystemHandler) ListDir(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	path := r.URL.Query().Get("path")
	if path == "" {
		path = "/"
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	uploadFilter := ""
	args := []interface{}{siteID, path}
	if uid := r.URL.Query().Get("upload_id"); uid != "" {
		parsed, parseErr := uuid.Parse(uid)
		if parseErr != nil {
			http.Error(w, "invalid upload_id", http.StatusBadRequest)
			return
		}
		uploadFilter = " AND upload_id = $3"
		args = append(args, parsed)
	}

	dirSQL := fmt.Sprintf(`
		SELECT DISTINCT data->>'file_name' AS name,
		       COUNT(*) AS file_count
		FROM events
		WHERE site_id = $1
		  AND event_type IN ('file_timeline', 'file_timeline_fn')
		  AND data->>'file_path' = $2
		  AND data->>'meta_type' = 'Dir'%s
		GROUP BY data->>'file_name'
		ORDER BY name`, uploadFilter)

	dirRows, err := h.DB.Query(r.Context(), dirSQL, args...)
	if err != nil {
		httpError(w, fmt.Errorf("query dirs: %w", err))
		return
	}
	defer dirRows.Close()

	var entries []fsEntry
	for dirRows.Next() {
		var name string
		var count int
		if err := dirRows.Scan(&name, &count); err != nil {
			httpError(w, err)
			return
		}
		entries = append(entries, fsEntry{
			Name:      name,
			IsDir:     true,
			FileCount: count,
		})
	}

	fileSQL := fmt.Sprintf(`
		SELECT data->>'file_name' AS name,
		       MAX((data->>'file_size')::bigint) FILTER (WHERE data->>'file_size' IS NOT NULL AND data->>'file_size' != '') AS size,
		       MAX(datetime::text) AS latest_time,
		       MAX(data->>'md5') FILTER (WHERE data->>'md5' IS NOT NULL AND data->>'md5' != '') AS md5,
		       MAX(data->>'sha256') FILTER (WHERE data->>'sha256' IS NOT NULL AND data->>'sha256' != '') AS sha256,
		       BOOL_OR(COALESCE((data->>'is_deleted')::boolean, false)) AS is_deleted,
		       BOOL_OR(data->>'timestompNote' IS NOT NULL AND data->>'timestompNote' != '') AS has_timestomp,
		       MAX(ct_significance) FILTER (WHERE ct_significance IS NOT NULL AND ct_significance != '') AS significance,
		       BOOL_OR(is_suspicious) AS is_suspicious
		FROM events
		WHERE site_id = $1
		  AND event_type IN ('file_timeline', 'file_timeline_fn')
		  AND data->>'file_path' = $2
		  AND (data->>'meta_type' IS NULL OR data->>'meta_type' != 'Dir')%s
		GROUP BY data->>'file_name'
		ORDER BY name`, uploadFilter)

	fileRows, err := h.DB.Query(r.Context(), fileSQL, args...)
	if err != nil {
		httpError(w, fmt.Errorf("query files: %w", err))
		return
	}
	defer fileRows.Close()

	for fileRows.Next() {
		var e fsEntry
		if err := fileRows.Scan(&e.Name, &e.Size, &e.LatestTime, &e.MD5, &e.SHA256,
			&e.IsDeleted, &e.HasTimestomp, &e.Significance, &e.IsSuspicious); err != nil {
			httpError(w, err)
			return
		}
		entries = append(entries, e)
	}

	if entries == nil {
		entries = []fsEntry{}
	}

	writeJSON(w, fsResponse{
		Path:    path,
		Entries: entries,
	})
}
