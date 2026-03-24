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
	"github.com/redis/go-redis/v9"
	"github.com/responseray/responseray/internal/db"
	"github.com/responseray/responseray/internal/handlers"
	"github.com/responseray/responseray/internal/ingest"
	"github.com/responseray/responseray/internal/rdb"
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

	redisAddr := envOr("REDIS_ADDR", "127.0.0.1:6379")
	redisClient, err := rdb.Connect(redisAddr)
	if err != nil {
		log.Fatalf("Redis connect: %v", err)
	}
	defer redisClient.Close()
	log.Printf("Connected to Redis at %s", redisAddr)

	recoverPendingUploads(ctx, pool, redisClient)

	ing := &ingest.Ingester{DB: pool}

	log.Println("Worker ready, waiting for jobs...")
	for {
		uploadID, err := rdb.DequeueUpload(ctx, redisClient, 5*time.Second)
		if err != nil {
			if err == redis.Nil {
				continue
			}
			log.Printf("dequeue error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		if err := processUpload(ctx, pool, redisClient, ing, uploadID); err != nil {
			log.Printf("process error for %s: %v", uploadID, err)
		}
	}
}

// recoverPendingUploads re-enqueues any pending or stuck processing uploads on startup.
func recoverPendingUploads(ctx context.Context, pool *pgxpool.Pool, rc *redis.Client) {
	rows, err := pool.Query(ctx,
		`SELECT id FROM uploads WHERE status IN ('pending', 'processing') ORDER BY created_at ASC`)
	if err != nil {
		log.Printf("Warning: failed to recover pending uploads: %v", err)
		return
	}
	defer rows.Close()

	// Reset any stuck 'processing' uploads back to pending
	pool.Exec(ctx, `UPDATE uploads SET status = 'pending', updated_at = NOW() WHERE status = 'processing'`)

	var count int
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			continue
		}
		if err := rdb.EnqueueUpload(ctx, rc, id); err != nil {
			log.Printf("Warning: failed to re-enqueue upload %s: %v", id, err)
			continue
		}
		rdb.SetProgressWithStart(ctx, rc, id, "queued", time.Now())
		count++
	}
	if count > 0 {
		log.Printf("Recovered %d pending upload(s) into Redis queue", count)
	}
}

func processUpload(ctx context.Context, pool *pgxpool.Pool, rc *redis.Client, ing *ingest.Ingester, uploadID uuid.UUID) error {
	var siteID uuid.UUID
	var filename string

	err := pool.QueryRow(ctx,
		`UPDATE uploads SET status = 'processing', updated_at = NOW()
		 WHERE id = $1 AND status = 'pending'
		 RETURNING site_id, filename`, uploadID).Scan(&siteID, &filename)
	if err != nil {
		if err.Error() == "no rows in result set" {
			log.Printf("Upload %s no longer pending, skipping", uploadID)
			rdb.ClearProgress(ctx, rc, uploadID)
			return nil
		}
		return fmt.Errorf("claim upload: %w", err)
	}

	log.Printf("Processing upload %s: %s", uploadID, filename)
	rdb.SetProgressWithStart(ctx, rc, uploadID, "analyzing", time.Now())

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
			setError(ctx, pool, rc, uploadID, fmt.Sprintf("ct-to-timesketch failed: %v", err))
			return fmt.Errorf("ct-to-timesketch: %w", err)
		}
	} else {
		log.Printf("JSONL already exists at %s, skipping ct-to-timesketch", outputPath)
	}

	log.Printf("ct-to-timesketch complete, counting lines...")
	rdb.UpdateProgressStage(ctx, rc, uploadID, "preparing")

	totalLines, err := ingest.CountLines(outputPath)
	if err != nil {
		log.Printf("Warning: could not count lines: %v", err)
		totalLines = 0
	}
	log.Printf("JSONL has %d lines, ingesting...", totalLines)

	rdb.UpdateProgressStage(ctx, rc, uploadID, "ingesting")
	rdb.UpdateProgressEvents(ctx, rc, uploadID, 0, totalLines)

	progressFn := func(processed, total int64) {
		rdb.UpdateProgressEvents(ctx, rc, uploadID, processed, total)
	}

	count, hostName, err := ing.IngestJSONL(ctx, outputPath, uploadID, siteID, progressFn)
	if err != nil {
		setError(ctx, pool, rc, uploadID, fmt.Sprintf("ingest failed: %v", err))
		return fmt.Errorf("ingest: %w", err)
	}

	log.Printf("Ingested %d events for upload %s (host: %s)", count, uploadID, hostName)

	log.Printf("Running remote access detection for upload %s...", uploadID)
	rdb.UpdateProgressStage(ctx, rc, uploadID, "detecting")

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

	rdb.ClearProgress(ctx, rc, uploadID)
	log.Printf("Upload %s complete", uploadID)
	return err
}

func setError(ctx context.Context, pool *pgxpool.Pool, rc *redis.Client, uploadID uuid.UUID, msg string) {
	pool.Exec(ctx,
		`UPDATE uploads SET status = 'error', error_msg = $2, updated_at = NOW() WHERE id = $1`,
		uploadID, msg)
	rdb.ClearProgress(ctx, rc, uploadID)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
