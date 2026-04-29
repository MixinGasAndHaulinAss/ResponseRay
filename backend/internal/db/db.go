package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

func ConnectString() string {
	host := envOr("POSTGRES_HOST", "localhost")
	port := envOr("POSTGRES_PORT", "5432")
	dbname := envOr("POSTGRES_DB", "responseray")
	user := envOr("POSTGRES_USER", "responseray")
	pass := envOr("POSTGRES_PASSWORD", "changeme_in_production")
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, pass, host, port, dbname)
}

func Connect(ctx context.Context) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(ConnectString())
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.MaxConns = 20

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}

	return pool, nil
}

func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	var version int
	err := pool.QueryRow(ctx, "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1").Scan(&version)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			log.Printf("No schema_version table, applying initial migration")
			version = 0
		} else {
			return fmt.Errorf("check version: %w", err)
		}
	}

	if version < 1 {
		log.Println("Applying migration 001_initial.sql")
		if _, err := pool.Exec(ctx, Migration001); err != nil {
			return fmt.Errorf("apply migration 001: %w", err)
		}
	}

	if version < 2 {
		log.Println("Applying migration 002_api_keys.sql")
		if _, err := pool.Exec(ctx, Migration002); err != nil {
			return fmt.Errorf("apply migration 002: %w", err)
		}
	}

	if version < 3 {
		log.Println("Applying migration 003_remote_access_results.sql")
		if _, err := pool.Exec(ctx, Migration003); err != nil {
			return fmt.Errorf("apply migration 003: %w", err)
		}
	}

	if version < 4 {
		log.Println("Applying migration 004_uploads_platform.sql")
		if _, err := pool.Exec(ctx, Migration004); err != nil {
			return fmt.Errorf("apply migration 004: %w", err)
		}
	}

	return nil
}

const Migration001 = `
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS sites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS uploads (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    site_id     UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    filename    TEXT NOT NULL,
    host_name   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',
    event_count BIGINT NOT NULL DEFAULT 0,
    error_msg   TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_uploads_site ON uploads(site_id);
CREATE INDEX IF NOT EXISTS idx_uploads_status ON uploads(status) WHERE status IN ('pending', 'processing');

CREATE TABLE IF NOT EXISTS events (
    id              BIGSERIAL PRIMARY KEY,
    upload_id       UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    site_id         UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    datetime        TIMESTAMPTZ NOT NULL,
    event_type      TEXT NOT NULL,
    data_type       TEXT,
    message         TEXT,
    host_name       TEXT,
    source_short    TEXT,
    timestamp_desc  TEXT,
    ct_significance TEXT,
    is_suspicious   BOOLEAN NOT NULL DEFAULT FALSE,
    finding         TEXT,
    finding_note    TEXT,
    data            JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_site_type ON events(site_id, event_type);
CREATE INDEX IF NOT EXISTS idx_events_site_datetime ON events(site_id, datetime);
CREATE INDEX IF NOT EXISTS idx_events_upload ON events(upload_id);
CREATE INDEX IF NOT EXISTS idx_events_notable ON events(site_id) WHERE ct_significance = 'LikelyNotable';
CREATE INDEX IF NOT EXISTS idx_events_suspicious ON events(site_id) WHERE is_suspicious = TRUE;
CREATE INDEX IF NOT EXISTS idx_events_findings ON events(site_id, finding) WHERE finding IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_events_data ON events USING gin(data);
CREATE INDEX IF NOT EXISTS idx_events_message_fts ON events USING gin(to_tsvector('english', COALESCE(message, '')));

CREATE TABLE IF NOT EXISTS schema_version (
    version INT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_version (version) VALUES (1) ON CONFLICT DO NOTHING;
`

const Migration002 = `
CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL,
    prefix      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used   TIMESTAMPTZ,
    is_active   BOOLEAN NOT NULL DEFAULT TRUE
);

INSERT INTO schema_version (version) VALUES (2) ON CONFLICT DO NOTHING;
`

const Migration003 = `
CREATE TABLE IF NOT EXISTS remote_access_results (
    id           BIGSERIAL PRIMARY KEY,
    upload_id    UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    site_id      UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    tool_name    TEXT NOT NULL,
    category     TEXT NOT NULL,
    event_count  BIGINT NOT NULL DEFAULT 0,
    event_types  TEXT[] NOT NULL DEFAULT '{}',
    first_seen   TIMESTAMPTZ,
    last_seen    TIMESTAMPTZ,
    search_terms TEXT[] NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ra_results_upload ON remote_access_results(upload_id);
CREATE INDEX IF NOT EXISTS idx_ra_results_site ON remote_access_results(site_id);

INSERT INTO schema_version (version) VALUES (3) ON CONFLICT DO NOTHING;
`

const Migration004 = `
ALTER TABLE uploads ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'unknown';
CREATE INDEX IF NOT EXISTS idx_uploads_platform ON uploads(site_id, platform);

INSERT INTO schema_version (version) VALUES (4) ON CONFLICT DO NOTHING;
`

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
