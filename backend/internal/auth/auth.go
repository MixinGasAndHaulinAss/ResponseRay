package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Middleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	password := os.Getenv("AUTH_PASSWORD")
	if password == "" {
		password = "changeme_in_production"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/health" {
				next.ServeHTTP(w, r)
				return
			}

			if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
				h := sha256.Sum256([]byte(apiKey))
				keyHash := hex.EncodeToString(h[:])

				var isActive bool
				err := pool.QueryRow(r.Context(),
					`UPDATE api_keys SET last_used = NOW() WHERE key_hash = $1 AND is_active = true RETURNING is_active`,
					keyHash).Scan(&isActive)
				if err == nil && isActive {
					ctx := context.WithValue(r.Context(), authMethodKey, "api_key")
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}

				http.Error(w, "Invalid API key", http.StatusUnauthorized)
				return
			}

			_, pass, ok := r.BasicAuth()
			if ok && subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1 {
				ctx := context.WithValue(r.Context(), authMethodKey, "password")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			w.Header().Set("WWW-Authenticate", `Basic realm="ResponseRay"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		})
	}
}

type contextKey string

const authMethodKey contextKey = "auth_method"

func GetAuthMethod(ctx context.Context) string {
	if v, ok := ctx.Value(authMethodKey).(string); ok {
		return v
	}
	return ""
}
