package lanepoller

import (
	"os"

	"github.com/google/uuid"
)

func uuidLike(s string) (uuid.UUID, error) { return uuid.Parse(s) }

func homeOf() string {
	h, _ := os.UserHomeDir()
	return h
}
