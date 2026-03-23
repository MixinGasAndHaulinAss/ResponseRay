package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/responseray/responseray/internal/auth"
	"github.com/responseray/responseray/internal/db"
	"github.com/responseray/responseray/internal/handlers"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("ResponseRay API starting...")

	ctx := context.Background()
	pool, err := db.Connect(ctx)
	if err != nil {
		log.Fatalf("DB connect: %v", err)
	}
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		log.Fatalf("Migration: %v", err)
	}
	log.Println("Database migrations applied")

	uploadDir := os.Getenv("UPLOAD_DIR")
	if uploadDir == "" {
		uploadDir = "/data/uploads"
	}
	artifactsDir := os.Getenv("ARTIFACTS_DIR")
	if artifactsDir == "" {
		artifactsDir = "/data/artifacts"
	}

	siteH := &handlers.SiteHandler{DB: pool}
	uploadH := &handlers.UploadHandler{DB: pool, UploadDir: uploadDir}
	eventH := &handlers.EventHandler{DB: pool}
	dashH := &handlers.DashboardHandler{DB: pool}
	fsH := &handlers.FilesystemHandler{DB: pool, ArtifactsDir: artifactsDir}
	logonH := &handlers.LogonHandler{DB: pool}
	raH := &handlers.RemoteAccessHandler{DB: pool}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	}))
	r.Use(auth.Middleware)

	r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	})

	r.Route("/api/sites", func(r chi.Router) {
		r.Get("/", siteH.List)
		r.Post("/", siteH.Create)

		r.Route("/{siteID}", func(r chi.Router) {
			r.Get("/", siteH.Get)
			r.Put("/", siteH.Update)
			r.Delete("/", siteH.Delete)

			r.Get("/dashboard", dashH.Stats)

			r.Get("/uploads", uploadH.List)
			r.Post("/uploads", uploadH.Upload)
			r.Post("/uploads/init", uploadH.InitChunkedUpload)
			r.Get("/uploads/{uploadID}", uploadH.Status)
			r.Delete("/uploads/{uploadID}", uploadH.Delete)
			r.Put("/uploads/{uploadID}/chunks/{chunkIdx}", uploadH.UploadChunk)
			r.Post("/uploads/{uploadID}/complete", uploadH.CompleteChunkedUpload)

			r.Get("/filesystem", fsH.ListDir)
			r.Get("/filesystem/download/{uploadID}", fsH.Download)
			r.Get("/remote-access", raH.Detect)
			r.Get("/logons/users", logonH.UserSummary)
			r.Get("/events", eventH.Query)
			r.Patch("/events/{eventID}/finding", eventH.UpdateFinding)
			r.Post("/events/findings", eventH.BulkUpdateFinding)
		})
	})

	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("API listening on :%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
