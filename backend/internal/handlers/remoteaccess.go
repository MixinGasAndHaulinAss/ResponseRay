package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RemoteAccessHandler struct {
	DB *pgxpool.Pool
}

type RemoteAccessTool struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	EventCount  int64    `json:"event_count"`
	EventTypes  []string `json:"event_types"`
	FirstSeen   *string  `json:"first_seen"`
	LastSeen    *string  `json:"last_seen"`
	SearchTerms []string `json:"search_terms"`
}

type toolDef struct {
	Name     string
	Category string
	Patterns []string
}

var KnownTools = []toolDef{
	{"TeamViewer", "Commercial RMM", []string{"teamviewer"}},
	{"AnyDesk", "Commercial RMM", []string{"anydesk"}},
	{"ConnectWise/ScreenConnect", "Commercial RMM", []string{"screenconnect", "connectwise"}},
	{"BeyondTrust/Bomgar", "Commercial RMM", []string{"bomgar", "beyondtrust", "beyondtrustcloud"}},
	{"LogMeIn", "Commercial RMM", []string{"logmein", "logme.in"}},
	{"Splashtop", "Commercial RMM", []string{"splashtop"}},
	{"GoTo/GoToAssist", "Commercial RMM", []string{"gotoassist", "gotomypc", "gotoopener"}},
	{"Dameware", "Commercial RMM", []string{"dameware"}},
	{"RemotePC", "Commercial RMM", []string{"remotepc"}},
	{"Atera", "Commercial RMM", []string{"atera"}},
	{"NinjaRMM", "Commercial RMM", []string{"ninjarmm", "ninjaone"}},
	{"Supremo", "Commercial RMM", []string{"supremo"}},
	{"RustDesk", "Open Source Remote", []string{"rustdesk"}},
	{"MeshAgent/MeshCentral", "Open Source Remote", []string{"meshagent", "meshcentral"}},
	{"VNC (various)", "Open Source Remote", []string{"vnc", "tightvnc", "ultravnc", "realvnc", "turbovnc"}},
	{"Ammyy Admin", "Dual-Use / Suspicious", []string{"ammyy"}},
	{"FleetDeck", "Dual-Use / Suspicious", []string{"fleetdeck"}},
	{"Action1", "Dual-Use / Suspicious", []string{"action1"}},
	{"SimpleHelp", "Dual-Use / Suspicious", []string{"simplehelp"}},
	{"Radmin", "Legacy Remote", []string{"radmin"}},
	{"NetSupport", "Dual-Use / Suspicious", []string{"netsupport"}},
	{"Ngrok", "Tunneling", []string{"ngrok"}},
	{"Cloudflared Tunnel", "Tunneling", []string{"cloudflared"}},
	{"Tailscale", "VPN/Mesh", []string{"tailscale"}},
	{"ZeroTier", "VPN/Mesh", []string{"zerotier"}},
	{"WireGuard", "VPN/Mesh", []string{"wireguard"}},
	{"psexec", "Lateral Movement", []string{"psexec"}},
	{"Windows Remote Desktop (mstsc)", "Built-in Remote", []string{"mstsc"}},
	{"Windows Remote Assistance", "Built-in Remote", []string{"msra.exe", "remote assistance"}},
	{"Quick Assist", "Built-in Remote", []string{"quickassist"}},
}

// DetectRemoteAccess runs the heavy LIKE-based scan against the events table
// and returns detected tools. Used by the worker during ingest and as a
// fallback for legacy uploads without cached results.
func DetectRemoteAccess(ctx context.Context, pool *pgxpool.Pool, siteID, uploadID uuid.UUID) ([]RemoteAccessTool, error) {
	var caseBranches []string
	for i, tool := range KnownTools {
		var pats []string
		for _, p := range tool.Patterns {
			pats = append(pats, fmt.Sprintf("lower(message) LIKE '%%%s%%'", strings.ToLower(p)))
		}
		caseBranches = append(caseBranches, fmt.Sprintf("WHEN %s THEN %d", strings.Join(pats, " OR "), i))
	}

	caseExpr := "CASE " + strings.Join(caseBranches, " ") + " ELSE -1 END"
	excludeTypes := "event_type NOT IN ('file_timeline', 'file_timeline_fn', 'srum_app_usage', 'srum_network_connectivity')"

	query := fmt.Sprintf(`
		SELECT tool_id,
			COUNT(*) AS cnt,
			array_agg(DISTINCT event_type) AS event_types,
			MIN(datetime)::text AS first_seen,
			MAX(datetime)::text AS last_seen
		FROM (
			SELECT event_type, datetime, %s AS tool_id
			FROM events
			WHERE site_id = $1 AND upload_id = $2 AND %s AND message IS NOT NULL
		) sub
		WHERE tool_id >= 0
		GROUP BY tool_id
		ORDER BY cnt DESC`, caseExpr, excludeTypes)

	rows, err := pool.Query(ctx, query, siteID, uploadID)
	if err != nil {
		return nil, fmt.Errorf("detect remote access query: %w", err)
	}
	defer rows.Close()

	var results []RemoteAccessTool
	for rows.Next() {
		var toolID int
		var count int64
		var eventTypes []string
		var firstSeen, lastSeen *string
		if err := rows.Scan(&toolID, &count, &eventTypes, &firstSeen, &lastSeen); err != nil {
			return nil, fmt.Errorf("scan remote access row: %w", err)
		}
		if toolID < 0 || toolID >= len(KnownTools) {
			continue
		}
		t := KnownTools[toolID]
		results = append(results, RemoteAccessTool{
			Name:        t.Name,
			Category:    t.Category,
			EventCount:  count,
			EventTypes:  eventTypes,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			SearchTerms: t.Patterns,
		})
	}

	if results == nil {
		results = []RemoteAccessTool{}
	}
	return results, nil
}

// StoreRemoteAccessResults writes detection results into remote_access_results.
func StoreRemoteAccessResults(ctx context.Context, pool *pgxpool.Pool, siteID, uploadID uuid.UUID, results []RemoteAccessTool) error {
	for _, r := range results {
		var firstSeen, lastSeen *time.Time
		if r.FirstSeen != nil {
			if t, err := time.Parse(time.RFC3339Nano, *r.FirstSeen); err == nil {
				firstSeen = &t
			} else if t, err := time.Parse("2006-01-02 15:04:05.999999-07", *r.FirstSeen); err == nil {
				firstSeen = &t
			}
		}
		if r.LastSeen != nil {
			if t, err := time.Parse(time.RFC3339Nano, *r.LastSeen); err == nil {
				lastSeen = &t
			} else if t, err := time.Parse("2006-01-02 15:04:05.999999-07", *r.LastSeen); err == nil {
				lastSeen = &t
			}
		}

		_, err := pool.Exec(ctx,
			`INSERT INTO remote_access_results
				(upload_id, site_id, tool_name, category, event_count, event_types, first_seen, last_seen, search_terms)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			uploadID, siteID, r.Name, r.Category, r.EventCount, r.EventTypes, firstSeen, lastSeen, r.SearchTerms)
		if err != nil {
			return fmt.Errorf("insert remote access result %q: %w", r.Name, err)
		}
	}
	return nil
}

// Detect serves GET /api/sites/{siteID}/remote-access.
// Reads from cached remote_access_results. Falls back to live detection
// for legacy uploads that were processed before caching was added.
func (h *RemoteAccessHandler) Detect(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	var uploadID *uuid.UUID
	if uid := r.URL.Query().Get("upload_id"); uid != "" {
		parsed, parseErr := uuid.Parse(uid)
		if parseErr != nil {
			http.Error(w, "invalid upload_id", http.StatusBadRequest)
			return
		}
		uploadID = &parsed
	}

	// Try cached results first
	results, err := h.loadCached(r.Context(), siteID, uploadID)
	if err != nil {
		httpError(w, err)
		return
	}

	// Fallback: if no cached results and a specific upload was requested,
	// run live detection once and cache for future requests.
	if len(results) == 0 && uploadID != nil {
		hasCached, checkErr := h.hasCachedResults(r.Context(), *uploadID)
		if checkErr != nil {
			httpError(w, checkErr)
			return
		}
		if !hasCached {
			log.Printf("No cached RA results for upload %s, running live detection and caching", *uploadID)
			live, detectErr := DetectRemoteAccess(r.Context(), h.DB, siteID, *uploadID)
			if detectErr != nil {
				httpError(w, detectErr)
				return
			}
			if err := StoreRemoteAccessResults(r.Context(), h.DB, siteID, *uploadID, live); err != nil {
				log.Printf("Warning: failed to cache RA results: %v", err)
			}
			results = live
		}
	}

	if results == nil {
		results = []RemoteAccessTool{}
	}
	writeJSON(w, results)
}

func (h *RemoteAccessHandler) loadCached(ctx context.Context, siteID uuid.UUID, uploadID *uuid.UUID) ([]RemoteAccessTool, error) {
	where := "site_id = $1"
	args := []interface{}{siteID}
	if uploadID != nil {
		where += " AND upload_id = $2"
		args = append(args, *uploadID)
	}

	query := fmt.Sprintf(
		`SELECT tool_name, category, event_count, event_types,
			first_seen::text, last_seen::text, search_terms
		 FROM remote_access_results WHERE %s ORDER BY event_count DESC`, where)

	rows, err := h.DB.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []RemoteAccessTool
	for rows.Next() {
		var t RemoteAccessTool
		if err := rows.Scan(&t.Name, &t.Category, &t.EventCount, &t.EventTypes,
			&t.FirstSeen, &t.LastSeen, &t.SearchTerms); err != nil {
			return nil, err
		}
		results = append(results, t)
	}
	return results, nil
}

func (h *RemoteAccessHandler) hasCachedResults(ctx context.Context, uploadID uuid.UUID) (bool, error) {
	var exists bool
	err := h.DB.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM remote_access_results WHERE upload_id = $1)`,
		uploadID).Scan(&exists)
	return exists, err
}
