package auth

import (
	"crypto/subtle"
	"net/http"
	"os"
)

func Middleware(next http.Handler) http.Handler {
	password := os.Getenv("AUTH_PASSWORD")
	if password == "" {
		password = "changeme_in_production"
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/health" {
			next.ServeHTTP(w, r)
			return
		}

		_, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pass), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="ResponseRay"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
