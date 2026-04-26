package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FilesystemHandler struct {
	DB           *pgxpool.Pool
	ArtifactsDir string
}

type fsEntry struct {
	Name         string  `json:"name"`
	IsDir        bool    `json:"is_dir"`
	Size         *int64  `json:"size,omitempty"`
	FileCount    int     `json:"file_count,omitempty"`
	LatestTime   *string `json:"latest_time,omitempty"`
	MD5          *string `json:"md5,omitempty"`
	SHA256       *string `json:"sha256,omitempty"`
	IsDeleted    bool    `json:"is_deleted,omitempty"`
	HasTimestomp bool    `json:"has_timestomp,omitempty"`
	Significance *string `json:"significance,omitempty"`
	IsSuspicious bool    `json:"is_suspicious,omitempty"`
	HasArtifact  bool    `json:"has_artifact,omitempty"`
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

	path := strings.ToLower(r.URL.Query().Get("path"))
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

	var dirSQL string
	var dirArgs []interface{}
	if path == "/" {
		// Root path: discover drive letter directories using fast EXISTS checks.
		dirArgs = []interface{}{siteID}
		rootUploadFilter := ""
		if uid := r.URL.Query().Get("upload_id"); uid != "" {
			parsed, _ := uuid.Parse(uid)
			rootUploadFilter = " AND upload_id = $2"
			dirArgs = append(dirArgs, parsed)
		}
		dirSQL = fmt.Sprintf(`
			SELECT letter AS name FROM (
			    VALUES ('a'),('b'),('c'),('d'),('e'),('f'),('g'),('h'),('i'),('j'),
			           ('k'),('l'),('m'),('n'),('o'),('p'),('q'),('r'),('s'),('t'),
			           ('u'),('v'),('w'),('x'),('y'),('z')
			) AS v(letter)
			WHERE EXISTS (
			    SELECT 1 FROM events
			    WHERE site_id = $1
			      AND event_type IN ('file_timeline', 'file_timeline_fn')
			      AND data->>'file_path' = '/' || letter || '/'%s
			    LIMIT 1
			)
			ORDER BY name`, rootUploadFilter)
	} else {
		dirArgs = args
		dirSQL = fmt.Sprintf(`
			SELECT DISTINCT data->>'file_name' AS name
			FROM events
			WHERE site_id = $1
			  AND event_type IN ('file_timeline', 'file_timeline_fn')
			  AND data->>'file_path' = $2
			  AND data->>'meta_type' = 'Dir'%s
			ORDER BY name`, uploadFilter)
	}

	dirRows, err := h.DB.Query(r.Context(), dirSQL, dirArgs...)
	if err != nil {
		httpError(w, fmt.Errorf("query dirs: %w", err))
		return
	}
	defer dirRows.Close()

	var entries []fsEntry
	for dirRows.Next() {
		var name string
		if err := dirRows.Scan(&name); err != nil {
			httpError(w, err)
			return
		}
		if name == "" {
			continue
		}
		entries = append(entries, fsEntry{
			Name:  name,
			IsDir: true,
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

	var uploadID string
	if uid := r.URL.Query().Get("upload_id"); uid != "" {
		uploadID = uid
	}

	for fileRows.Next() {
		var e fsEntry
		if err := fileRows.Scan(&e.Name, &e.Size, &e.LatestTime, &e.MD5, &e.SHA256,
			&e.IsDeleted, &e.HasTimestomp, &e.Significance, &e.IsSuspicious); err != nil {
			httpError(w, err)
			return
		}
		if uploadID != "" && h.ArtifactsDir != "" {
			diskPath := h.artifactDiskPath(uploadID, path, e.Name)
			if _, err := os.Stat(diskPath); err == nil {
				e.HasArtifact = true
			}
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

// artifactDiskPath converts a UI path + filename to the on-disk artifact path.
// UI paths look like "/c/windows/system32/" where the first component is the
// drive letter. The artifact dir structure is
// {artifactsDir}/{uploadID}/{path without leading slash}/{filename}
func (h *FilesystemHandler) artifactDiskPath(uploadID, uiPath, filename string) string {
	rel := strings.TrimPrefix(uiPath, "/")
	rel = strings.TrimSuffix(rel, "/")

	primary := filepath.Join(h.ArtifactsDir, uploadID, rel, filename)
	if _, err := os.Stat(primary); err == nil {
		return primary
	}

	lowered := filepath.Join(h.ArtifactsDir, uploadID, strings.ToLower(rel), filename)
	if _, err := os.Stat(lowered); err == nil {
		return lowered
	}

	// Try without the drive letter prefix (legacy artifacts stored without it)
	parts := strings.SplitN(rel, "/", 2)
	if len(parts) == 2 && len(parts[0]) == 1 {
		withoutDrive := filepath.Join(h.ArtifactsDir, uploadID, parts[1], filename)
		if _, err := os.Stat(withoutDrive); err == nil {
			return withoutDrive
		}
	}

	return primary
}

func (h *FilesystemHandler) Download(w http.ResponseWriter, r *http.Request) {
	uploadID := chi.URLParam(r, "uploadID")
	if _, err := uuid.Parse(uploadID); err != nil {
		http.Error(w, "invalid upload ID", http.StatusBadRequest)
		return
	}

	filePath := r.URL.Query().Get("path")
	fileName := r.URL.Query().Get("name")
	if filePath == "" || fileName == "" {
		http.Error(w, "path and name are required", http.StatusBadRequest)
		return
	}

	if strings.Contains(fileName, "/") || strings.Contains(fileName, "\\") ||
		strings.Contains(fileName, "..") || strings.Contains(filePath, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}

	diskPath := h.artifactDiskPath(uploadID, filePath, fileName)

	if _, err := os.Stat(diskPath); os.IsNotExist(err) {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
	http.ServeFile(w, r, diskPath)
}
