CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE sites (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE uploads (
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

CREATE INDEX idx_uploads_site ON uploads(site_id);
CREATE INDEX idx_uploads_status ON uploads(status) WHERE status IN ('pending', 'processing');

CREATE TABLE events (
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

CREATE INDEX idx_events_site_type ON events(site_id, event_type);
CREATE INDEX idx_events_site_datetime ON events(site_id, datetime);
CREATE INDEX idx_events_upload ON events(upload_id);
CREATE INDEX idx_events_notable ON events(site_id) WHERE ct_significance = 'LikelyNotable';
CREATE INDEX idx_events_suspicious ON events(site_id) WHERE is_suspicious = TRUE;
CREATE INDEX idx_events_findings ON events(site_id, finding) WHERE finding IS NOT NULL;
CREATE INDEX idx_events_data ON events USING gin(data);
CREATE INDEX idx_events_message_fts ON events USING gin(to_tsvector('english', COALESCE(message, '')));

CREATE TABLE schema_version (
    version INT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_version (version) VALUES (1);
