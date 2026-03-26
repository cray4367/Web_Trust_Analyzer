package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

// rdb is the package-level Redis client.
// It is nil when Redis is unavailable; all callers must fall back gracefully.
var rdb *redis.Client

// InitRedis dials Redis using REDIS_URL from the environment.
// If the variable is missing or the server is unreachable, rdb stays nil
// and the firewall continues operating with in-memory fallback.
func InitRedis() {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		log.Println("⚠️  REDIS_URL not set — rate limits and trust cache will use in-memory fallback")
		return
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		log.Printf("⚠️  Invalid REDIS_URL (%s): %v — using in-memory fallback\n", redisURL, err)
		return
	}

	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := client.Ping(ctx).Result(); err != nil {
		log.Printf("⚠️  Redis unreachable at %s: %v — using in-memory fallback\n", redisURL, err)
		return
	}

	rdb = client
	log.Printf("✅  Redis connected at %s\n", redisURL)
}

// CloseRedis shuts down the Redis connection cleanly.
func CloseRedis() {
	if rdb != nil {
		if err := rdb.Close(); err != nil {
			log.Printf("Error closing Redis: %v\n", err)
		}
	}
}

// redisAvailable is a convenience helper used by rate limiter and trust cache.
func redisAvailable() bool {
	return rdb != nil
}
