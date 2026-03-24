package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type APIKeyHandler struct {
	DB *pgxpool.Pool
}

type apiKeyResponse struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used"`
	IsActive  bool       `json:"is_active"`
}

type apiKeyCreateResponse struct {
	apiKeyResponse
	Key string `json:"key"`
}

func generateAPIKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "rr_" + hex.EncodeToString(b), nil
}

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(r.Context(),
		`SELECT id, name, prefix, created_at, last_used, is_active
		 FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		httpError(w, err)
		return
	}
	defer rows.Close()

	var keys []apiKeyResponse
	for rows.Next() {
		var k apiKeyResponse
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &k.CreatedAt, &k.LastUsed, &k.IsActive); err != nil {
			httpError(w, err)
			return
		}
		keys = append(keys, k)
	}
	if keys == nil {
		keys = []apiKeyResponse{}
	}

	writeJSON(w, keys)
}

func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	rawKey, err := generateAPIKey()
	if err != nil {
		httpError(w, err)
		return
	}

	id := uuid.New()
	now := time.Now()
	prefix := rawKey[:11] // "rr_" + first 8 hex chars

	_, err = h.DB.Exec(r.Context(),
		`INSERT INTO api_keys (id, name, key_hash, prefix, created_at, is_active) VALUES ($1, $2, $3, $4, $5, true)`,
		id, req.Name, hashKey(rawKey), prefix, now)
	if err != nil {
		httpError(w, err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, apiKeyCreateResponse{
		apiKeyResponse: apiKeyResponse{
			ID:        id,
			Name:      req.Name,
			Prefix:    prefix,
			CreatedAt: now,
			IsActive:  true,
		},
		Key: rawKey,
	})
}

func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	keyID, err := uuid.Parse(chi.URLParam(r, "keyID"))
	if err != nil {
		http.Error(w, "invalid key ID", http.StatusBadRequest)
		return
	}

	_, err = h.DB.Exec(r.Context(), `DELETE FROM api_keys WHERE id = $1`, keyID)
	if err != nil {
		httpError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
