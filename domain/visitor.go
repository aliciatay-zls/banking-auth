package domain

import (
	"golang.org/x/time/rate"
	"time"
)

const LastSeenBeforeCleanupInterval = 3 * time.Minute
const CleanupInterval = time.Minute

type Visitor struct { //business/domain object
	IPAddr   string
	Limiter  *rate.Limiter
	LastSeen time.Time
}

func NewVisitor(ip string) *Visitor {
	return &Visitor{
		IPAddr:   ip,
		Limiter:  rate.NewLimiter(1, 1), //strictly 1 request per second
		LastSeen: time.Now(),
	}
}
