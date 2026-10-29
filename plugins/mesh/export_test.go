package mesh

import "time"

// NoStageBackoff makes Stage retries immediate; the returned func restores it.
func NoStageBackoff() func() {
	old := stageBackoff
	stageBackoff = time.Millisecond
	return func() { stageBackoff = old }
}

// PendingLen is the number of token values the extension provider still holds.
func PendingLen(e *ExtSelf) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.pending)
}
