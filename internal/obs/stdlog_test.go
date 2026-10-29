package obs

import (
	"io"
	"log"
)

// captureStdLog points the process-wide log package at w until restored.
func captureStdLog(w io.Writer) (restore func()) {
	prev := log.Writer()
	log.SetOutput(w)
	return func() { log.SetOutput(prev) }
}
