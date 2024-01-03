package domain

import (
	"sync"
	"time"
)

//Reference: https://www.alexedwards.net/blog/how-to-rate-limit-http-requests

type VisitorRepository interface { //repo (secondary port)
	GetVisitor(string) *Visitor
	Cleanup()
}

type DefaultVisitorRepository struct { //adapter
	mu          sync.Mutex
	visitorsMap map[string]*Visitor
}

func NewDefaultVisitorRepository() *DefaultVisitorRepository {
	return &DefaultVisitorRepository{visitorsMap: make(map[string]*Visitor)}
}

// GetVisitor retrieves the entry for the given IP address, creating an entry if it does not exist yet,
// and updates/sets the time that it last visited the site to the current time.
func (r *DefaultVisitorRepository) GetVisitor(ip string) *Visitor {
	r.mu.Lock()
	defer r.mu.Unlock()

	v, ok := r.visitorsMap[ip]
	if !ok {
		visitor := NewVisitor(ip)
		r.visitorsMap[ip] = visitor
		return visitor
	}
	v.LastSeen = time.Now()
	return v
}

// Cleanup removes outdated IP addresses (last visited the site more than 3 minutes ago) every 1 minute, indefinitely.
func (r *DefaultVisitorRepository) Cleanup() {
	for {
		time.Sleep(CleanupInterval)

		r.mu.Lock()
		for k, v := range r.visitorsMap {
			if time.Now().Sub(v.LastSeen) > LastSeenBeforeCleanupInterval {
				delete(r.visitorsMap, k)
			}
		}
		r.mu.Unlock()
	}
}
