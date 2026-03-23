package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RemoteAccessHandler struct {
	DB *pgxpool.Pool
}

type remoteAccessTool struct {
	Name         string   `json:"name"`
	Category     string   `json:"category"`
	EventCount   int64    `json:"event_count"`
	EventTypes   []string `json:"event_types"`
	FirstSeen    *string  `json:"first_seen"`
	LastSeen     *string  `json:"last_seen"`
	SearchTerms  []string `json:"search_terms"`
}

var knownTools = []struct {
	Name     string
	Category string
	Patterns []string
}{
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

	var results []remoteAccessTool

	for _, tool := range knownTools {
		ilikeClauses := ""
		for i, p := range tool.Patterns {
			if i > 0 {
				ilikeClauses += " OR "
			}
			ilikeClauses += "message ILIKE '%" + p + "%'"
		}

		query := `SELECT COUNT(*),
			array_agg(DISTINCT event_type),
			MIN(datetime)::text,
			MAX(datetime)::text
		FROM events
		WHERE site_id = $1 AND (` + ilikeClauses + `)`

		var count int64
		var eventTypes []string
		var firstSeen, lastSeen *string

		err := h.DB.QueryRow(r.Context(), query, siteID).Scan(&count, &eventTypes, &firstSeen, &lastSeen)
		if err != nil || count == 0 {
			continue
		}

		results = append(results, remoteAccessTool{
			Name:        tool.Name,
			Category:    tool.Category,
			EventCount:  count,
			EventTypes:  eventTypes,
			FirstSeen:   firstSeen,
			LastSeen:    lastSeen,
			SearchTerms: tool.Patterns,
		})
	}

	if results == nil {
		results = []remoteAccessTool{}
	}

	writeJSON(w, results)
}
