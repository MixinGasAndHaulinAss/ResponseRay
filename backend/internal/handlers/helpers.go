package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
)

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("json encode error: %v", err)
	}
}

func httpError(w http.ResponseWriter, err error) {
	if strings.Contains(err.Error(), "no rows") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	log.Printf("handler error: %v", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return v
}
