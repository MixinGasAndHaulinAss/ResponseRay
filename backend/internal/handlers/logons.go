package handlers

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type LogonHandler struct {
	DB *pgxpool.Pool
}

type logonUserSummary struct {
	Username     string  `json:"username"`
	TotalEvents  int64   `json:"total_events"`
	SuccessCount int64   `json:"success_count"`
	FailCount    int64   `json:"fail_count"`
	UniqueIPs    int64   `json:"unique_ips"`
	FirstSeen    string  `json:"first_seen"`
	LastSeen     string  `json:"last_seen"`
	AuthPackages string  `json:"auth_packages"`
	LogonTypes   string  `json:"logon_types"`
	Domain       *string `json:"domain,omitempty"`
}

func (h *LogonHandler) UserSummary(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteID"))
	if err != nil {
		http.Error(w, "invalid site ID", http.StatusBadRequest)
		return
	}

	where := "site_id = $1"
	args := []interface{}{siteID}
	argIdx := 2
	if uid := r.URL.Query().Get("upload_id"); uid != "" {
		parsed, parseErr := uuid.Parse(uid)
		if parseErr != nil {
			http.Error(w, "invalid upload_id", http.StatusBadRequest)
			return
		}
		where += fmt.Sprintf(" AND upload_id = $%d", argIdx)
		args = append(args, parsed)
		argIdx++
	}

	sql := fmt.Sprintf(`
		SELECT
			COALESCE(data->>'TargetUserName', data->>'User', 'unknown') AS username,
			COUNT(*) AS total_events,
			COUNT(*) FILTER (WHERE data->>'event_identifier' = '4624') AS success_count,
			COUNT(*) FILTER (WHERE data->>'event_identifier' = '4625') AS fail_count,
			COUNT(DISTINCT data->>'IpAddress') FILTER (
				WHERE data->>'IpAddress' IS NOT NULL
				AND data->>'IpAddress' != ''
				AND data->>'IpAddress' != '-'
			) AS unique_ips,
			MIN(datetime)::text AS first_seen,
			MAX(datetime)::text AS last_seen,
			STRING_AGG(DISTINCT data->>'AuthenticationPackageName', ', ')
				FILTER (WHERE data->>'AuthenticationPackageName' IS NOT NULL
				AND data->>'AuthenticationPackageName' != '') AS auth_packages,
			STRING_AGG(DISTINCT data->>'LogonType', ', ')
				FILTER (WHERE data->>'LogonType' IS NOT NULL
				AND data->>'LogonType' != '') AS logon_types,
			MAX(data->>'TargetDomainName')
				FILTER (WHERE data->>'TargetDomainName' IS NOT NULL
				AND data->>'TargetDomainName' != ''
				AND data->>'TargetDomainName' != '-') AS domain
		FROM events
		WHERE %s
		  AND event_type IN ('windows_logon', 'windows_authentication', 'windows_rdp', 'session_logon')
		GROUP BY COALESCE(data->>'TargetUserName', data->>'User', 'unknown')
		ORDER BY total_events DESC`, where)

	rows, err := h.DB.Query(r.Context(), sql, args...)
	if err != nil {
		httpError(w, fmt.Errorf("query logon users: %w", err))
		return
	}
	defer rows.Close()

	var users []logonUserSummary
	for rows.Next() {
		var u logonUserSummary
		var authPkg, logonTypes *string
		if err := rows.Scan(&u.Username, &u.TotalEvents, &u.SuccessCount, &u.FailCount,
			&u.UniqueIPs, &u.FirstSeen, &u.LastSeen, &authPkg, &logonTypes, &u.Domain); err != nil {
			httpError(w, err)
			return
		}
		if authPkg != nil {
			u.AuthPackages = *authPkg
		}
		if logonTypes != nil {
			u.LogonTypes = *logonTypes
		}
		users = append(users, u)
	}
	if users == nil {
		users = []logonUserSummary{}
	}

	writeJSON(w, users)
}
