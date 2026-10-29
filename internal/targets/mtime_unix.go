//go:build unix

package targets

import (
	"time"

	"golang.org/x/sys/unix"
)

func statMtime(st *unix.Stat_t) time.Time { return time.Unix(st.Mtim.Unix()) }
