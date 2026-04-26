package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

	lowerName := strings.ToLower(filename)
	isCollectorZip := strings.HasSuffix(lowerName, ".zip")
	isCollectorTar := strings.HasSuffix(lowerName, ".tar.gz") || strings.HasSuffix(lowerName, ".tgz")
	isCollectorArchive := isCollectorZip || isCollectorTar

	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		var cmd *exec.Cmd

		if isCollectorArchive {
			// ResponseRay Collector archive (.zip from Windows; .tar.gz from
			// Linux/macOS/ESXi). Extract and run ct-to-timesketch in --directory mode.
			extractDir := filepath.Join(uploadDir, uploadID.String(), "extracted")
			os.MkdirAll(extractDir, 0755)

			log.Printf("Extracting collector archive %s...", filename)
			var extractErr error
			if isCollectorZip {
				extractErr = extractZip(inputPath, extractDir)
			} else {
				extractErr = extractTarGz(inputPath, extractDir)
			}
			if extractErr != nil {
				setError(ctx, pool, rc, uploadID, fmt.Sprintf("archive extraction failed: %v", extractErr))
				return fmt.Errorf("archive extraction: %w", extractErr)
			}

		// Find the actual directory containing manifest.json
		manifestDir := findManifestDir(extractDir)
		if manifestDir == "" {
			setError(ctx, pool, rc, uploadID, "manifest.json not found in zip archive")
			return fmt.Errorf("manifest.json not found in extracted zip")
		}

		cmd = exec.CommandContext(ctx, ctBinary,
			"--directory", manifestDir,
			"--output", outputPath,
			"--artifacts-dir", artifactDir,
			"--cloudrules")
		} else {
			// CyberTriage .json.gz -- existing flow
			cmd = exec.CommandContext(ctx, ctBinary, inputPath,
				"--output", outputPath,
				"--artifacts-dir", artifactDir,
				"--cloudrules")
		}

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

// findManifestDir walks the extracted directory to find manifest.json,
// handling zips that contain a top-level wrapper folder.
func findManifestDir(root string) string {
	if _, err := os.Stat(filepath.Join(root, "manifest.json")); err == nil {
		return root
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			candidate := filepath.Join(root, e.Name())
			if _, err := os.Stat(filepath.Join(candidate, "manifest.json")); err == nil {
				return candidate
			}
		}
	}
	return ""
}

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		target := filepath.Join(destDir, f.Name)

		// Prevent zip slip
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(target, 0755)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}

		zrc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %s: %w", f.Name, err)
		}

		dst, err := os.Create(target)
		if err != nil {
			zrc.Close()
			return fmt.Errorf("create %s: %w", target, err)
		}

		_, err = io.Copy(dst, zrc)
		zrc.Close()
		dst.Close()
		if err != nil {
			return fmt.Errorf("copy %s: %w", f.Name, err)
		}
	}
	return nil
}

// extractTarGz extracts a gzipped tar archive (produced by the Linux, macOS,
// and ESXi collectors) into destDir.
func extractTarGz(archivePath, destDir string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar next: %w", err)
		}

		target := filepath.Join(destDir, hdr.Name)
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, 0755)
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("create %s: %w", target, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("copy %s: %w", hdr.Name, err)
			}
			out.Close()
		case tar.TypeSymlink, tar.TypeLink:
			// Skip links to keep extraction sandboxed and predictable.
			continue
		}
	}
	return nil
}
