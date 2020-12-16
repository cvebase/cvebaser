package lint

import (
	"sync/atomic"
	"time"
)

type Stats struct {
	StartedAt  time.Time
	FinishedAt time.Time
	Successful uint32
	Failed     uint32
}

func (st *Stats) Duration() time.Duration {
	return st.FinishedAt.Sub(st.StartedAt)
}

func (st *Stats) IncrementSuccessful() {
	atomic.AddUint32(&st.Successful, 1)
}

func (st *Stats) IncrementFailed() {
	atomic.AddUint32(&st.Failed, 1)
}
