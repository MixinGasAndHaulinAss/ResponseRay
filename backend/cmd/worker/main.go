package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/responseray/responseray/internal/db"
	"github.com/responseray/responseray/internal/handlers"
	"github.com/responseray/responseray/internal/ingest"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("ResponseRay Worker starting...")

	ctx := context.Background()
	pool, err := db.Connect(ctx)
	if err != nil {
		log.Fatalf("DB connect: %v", err)
	}
	defer pool.Close()

	ing := &ingest.Ingester{DB: pool}

	for {
		if err := processNext(ctx, pool, ing); err != nil {
			log.Printf("process error: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func processNext(ctx context.Context, pool *pgxpool.Pool, ing *ingest.Ingester) error {
	var uploadID uuid.UUID
	var siteID uuid.UUID
	var filename string

	err := pool.QueryRow(ctx,
		`UPDATE uploads SET status = 'processing', updated_at = NOW()
		 WHERE id = (SELECT id FROM uploads WHERE status = 'pending' ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED)
		 RETURNING id, site_id, filename`).
		Scan(&uploadID, &siteID, &filename)
	if err != nil {
		if err.Error() == "no rows in result set" {
			return nil
		}
		return fmt.Errorf("claim upload: %w", err)
	}

	log.Printf("Processing upload %s: %s", uploadID, filename)

	uploadDir := envOr("UPLOAD_DIR", "/data/uploads")
	artifactsDir := envOr("ARTIFACTS_DIR", "/data/artifacts")
	reportsDir := envOr("REPORTS_DIR", "/data/reports")
	ctBinary := envOr("CT_BINARY_PATH", "/usr/local/bin/ct-to-timesketch")

	inputPath := filepath.Join(uploadDir, uploadID.String(), filename)
	outputDir := filepath.Join(reportsDir, uploadID.String())
	artifactDir := filepath.Join(artifactsDir, uploadID.String())

	os.MkdirAll(outputDir, 0755)
	os.MkdirAll(artifactDir, 0755)

	outputPath := filepath.Join(outputDir, "timeline.jsonl")

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		cmd := exec.CommandContext(ctx, ctBinary, inputPath,
			"--output", outputPath,
			"--artifacts-dir", artifactDir,
			"--cloudrules")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			setError(ctx, pool, uploadID, fmt.Sprintf("ct-to-timesketch failed: %v", err))
			return fmt.Errorf("ct-to-timesketch: %w", err)
		}
	} else {
		log.Printf("JSONL already exists at %s, skipping ct-to-timesketch", outputPath)
	}

	log.Printf("ct-to-timesketch complete, ingesting JSONL...")

	count, hostName, err := ing.IngestJSONL(ctx, outputPath, uploadID, siteID)
	if err != nil {
		setError(ctx, pool, uploadID, fmt.Sprintf("ingest failed: %v", err))
		return fmt.Errorf("ingest: %w", err)
	}

	log.Printf("Ingested %d events for upload %s (host: %s)", count, uploadID, hostName)

	log.Printf("Running remote access detection for upload %s...", uploadID)
	raResults, raErr := handlers.DetectRemoteAccess(ctx, pool, siteID, uploadID)
	if raErr != nil {
		log.Printf("Warning: remote access detection failed: %v", raErr)
	} else {
		if err := handlers.StoreRemoteAccessResults(ctx, pool, siteID, uploadID, raResults); err != nil {
			log.Printf("Warning: failed to store remote access results: %v", err)
		} else {
			log.Printf("Detected %d remote access tools for upload %s", len(raResults), uploadID)
		}
	}

	_, err = pool.Exec(ctx,
		`UPDATE uploads SET status = 'complete', event_count = $2, host_name = $3, updated_at = NOW() WHERE id = $1`,
		uploadID, count, hostName)
	return err
}

func setError(ctx context.Context, pool *pgxpool.Pool, uploadID uuid.UUID, msg string) {
	pool.Exec(ctx,
		`UPDATE uploads SET status = 'error', error_msg = $2, updated_at = NOW() WHERE id = $1`,
		uploadID, msg)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
