package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RemoteAccessHandler struct {
	DB *pgxpool.Pool
}

type remoteAccessTool struct {
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

var knownTools = []toolDef{
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

func (h *RemoteAccessHandler) Detect(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
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

	// Build a single CASE expression that classifies each row into a tool_id
	// by checking lower(message) against all patterns, then aggregate once.
	var caseBranches []string
	for i, tool := range knownTools {
		var pats []string
		for _, p := range tool.Patterns {
			pats = append(pats, fmt.Sprintf("lower(message) LIKE '%%%s%%'", strings.ToLower(p)))
		}
		caseBranches = append(caseBranches, fmt.Sprintf("WHEN %s THEN %d", strings.Join(pats, " OR "), i))
	}

	caseExpr := "CASE " + strings.Join(caseBranches, " ") + " ELSE -1 END"

	query := fmt.Sprintf(`
		SELECT tool_id,
			COUNT(*) AS cnt,
			array_agg(DISTINCT event_type) AS event_types,
			MIN(datetime)::text AS first_seen,
			MAX(datetime)::text AS last_seen
		FROM (
			SELECT event_type, datetime, %s AS tool_id
			FROM events
			WHERE %s AND message IS NOT NULL
		) sub
		WHERE tool_id >= 0
		GROUP BY tool_id
		ORDER BY cnt DESC`, caseExpr, where)

	rows, err := h.DB.Query(r.Context(), query, args...)
	if err != nil {
		httpError(w, err)
		return
	}
	defer rows.Close()

	var results []remoteAccessTool
	for rows.Next() {
		var toolID int
		var count int64
		var eventTypes []string
		var firstSeen, lastSeen *string
		if err := rows.Scan(&toolID, &count, &eventTypes, &firstSeen, &lastSeen); err != nil {
			httpError(w, err)
			return
		}
		if toolID < 0 || toolID >= len(knownTools) {
			continue
		}
		t := knownTools[toolID]
		results = append(results, remoteAccessTool{
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
		results = []remoteAccessTool{}
	}

	writeJSON(w, results)
}
