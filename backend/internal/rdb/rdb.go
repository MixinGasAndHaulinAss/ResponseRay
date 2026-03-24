package rdb

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	QueueKey      = "responseray:queue"
	progressPrefix = "responseray:progress:"
	progressTTL    = 24 * time.Hour
)

func Connect(addr string) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr: addr,
	})
	if err := client.Ping(context.Background()).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return client, nil
}

func EnqueueUpload(ctx context.Context, client *redis.Client, uploadID uuid.UUID) error {
	return client.LPush(ctx, QueueKey, uploadID.String()).Err()
}

// DequeueUpload blocks until a job is available. Returns the upload ID.
// Returns uuid.Nil and redis.Nil error when the timeout expires with no job.
func DequeueUpload(ctx context.Context, client *redis.Client, timeout time.Duration) (uuid.UUID, error) {
	result, err := client.BRPop(ctx, timeout, QueueKey).Result()
	if err != nil {
		return uuid.Nil, err
	}
	// result[0] = key name, result[1] = value
	return uuid.Parse(result[1])
}

type Progress struct {
	Stage           string `json:"stage"`
	EventsProcessed int64  `json:"events_processed"`
	EventsTotal     int64  `json:"events_total"`
	StartedAt       string `json:"started_at"`
}

func SetProgress(ctx context.Context, client *redis.Client, uploadID uuid.UUID, stage string, eventsProcessed, eventsTotal int64) error {
	key := progressPrefix + uploadID.String()
	pipe := client.Pipeline()
	pipe.HSet(ctx, key, map[string]interface{}{
		"stage":            stage,
		"events_processed": eventsProcessed,
		"events_total":     eventsTotal,
		"started_at":       "", // set once below
	})
	pipe.Expire(ctx, key, progressTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func SetProgressWithStart(ctx context.Context, client *redis.Client, uploadID uuid.UUID, stage string, startedAt time.Time) error {
	key := progressPrefix + uploadID.String()
	pipe := client.Pipeline()
	pipe.HSet(ctx, key, map[string]interface{}{
		"stage":            stage,
		"events_processed": 0,
		"events_total":     0,
		"started_at":       startedAt.UTC().Format(time.RFC3339),
	})
	pipe.Expire(ctx, key, progressTTL)
	_, err := pipe.Exec(ctx)
	return err
}

func UpdateProgressStage(ctx context.Context, client *redis.Client, uploadID uuid.UUID, stage string) error {
	key := progressPrefix + uploadID.String()
	return client.HSet(ctx, key, "stage", stage).Err()
}

func UpdateProgressEvents(ctx context.Context, client *redis.Client, uploadID uuid.UUID, processed, total int64) error {
	key := progressPrefix + uploadID.String()
	return client.HSet(ctx, key, map[string]interface{}{
		"events_processed": processed,
		"events_total":     total,
	}).Err()
}

func GetProgress(ctx context.Context, client *redis.Client, uploadID uuid.UUID) (*Progress, error) {
	key := progressPrefix + uploadID.String()
	vals, err := client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if len(vals) == 0 {
		return nil, nil
	}

	processed, _ := strconv.ParseInt(vals["events_processed"], 10, 64)
	total, _ := strconv.ParseInt(vals["events_total"], 10, 64)

	return &Progress{
		Stage:           vals["stage"],
		EventsProcessed: processed,
		EventsTotal:     total,
		StartedAt:       vals["started_at"],
	}, nil
}

func ClearProgress(ctx context.Context, client *redis.Client, uploadID uuid.UUID) error {
	return client.Del(ctx, progressPrefix+uploadID.String()).Err()
}

func QueueLength(ctx context.Context, client *redis.Client) (int64, error) {
	return client.LLen(ctx, QueueKey).Result()
}

func QueuePosition(ctx context.Context, client *redis.Client, uploadID uuid.UUID) (int64, error) {
	// LPOS finds position from head (left). Since we LPUSH and BRPOP (right),
	// position 0 is the newest item and the last position is next to be processed.
	// We return the position from the processing end (right side).
	pos, err := client.LPos(ctx, QueueKey, uploadID.String(), redis.LPosArgs{}).Result()
	if err != nil {
		if err == redis.Nil {
			return -1, nil
		}
		return -1, err
	}
	length, err := client.LLen(ctx, QueueKey).Result()
	if err != nil {
		return -1, err
	}
	// Convert to 1-based position from the right (processing end)
	return length - pos, nil
}
