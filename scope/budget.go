package scope

import (
	"fmt"
	"sync"
)

// BudgetLedger accounts for operations across all servers of a mission. The
// signed per-server split is authoritative: a server may never borrow another
// server's share, and no server falls back to the mission total.
type BudgetLedger interface {
	Spent(missionID, server string) (int, error)
	Reserve(missionID, server string, n int) (remaining int, err error)
	Release(missionID, server string, n int) error
}

// MemoryLedger is the reference in-process ledger. A durable server replaces it
// with an append-only implementation; the interface and the per-server split
// stay the same.
type MemoryLedger struct {
	mu        sync.Mutex
	total     int
	perServer map[string]int
	spent     map[string]int // key mission+"\x00"+server
}

// NewMemoryLedger builds a ledger from the signed budget. total==0 with no
// per-server entries means unlimited.
func NewMemoryLedger(total int, perServer map[string]int) *MemoryLedger {
	caps := make(map[string]int, len(perServer))
	for k, v := range perServer {
		caps[k] = v
	}
	return &MemoryLedger{total: total, perServer: caps, spent: map[string]int{}}
}

func ledgerKey(missionID, server string) string { return missionID + "\x00" + server }

// Allocation returns the signed cap for server and whether a split was defined.
func (l *MemoryLedger) Allocation(server string) (int, bool) {
	cap, ok := l.perServer[server]
	return cap, ok
}

func (l *MemoryLedger) Spent(missionID, server string) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.spent[ledgerKey(missionID, server)], nil
}

func (l *MemoryLedger) Reserve(missionID, server string, n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("scope: reserve count must be positive")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := ledgerKey(missionID, server)
	used := l.spent[key]
	cap, hasCap := l.perServer[server]
	unlimited := l.total == 0 && len(l.perServer) == 0
	if !unlimited {
		if !hasCap {
			return 0, &DeniedError{Code: CodeBudgetExhausted, Reason: fmt.Sprintf("server %q has no signed budget allocation", server)}
		}
		if used+n > cap {
			return maxInt(cap-used, 0), &DeniedError{Code: CodeBudgetExhausted,
				Reason: fmt.Sprintf("server %q used %d of its %d operations", server, used, cap)}
		}
	}
	if l.total > 0 {
		sum := 0
		for _, v := range l.spent {
			sum += v
		}
		if sum+n > l.total {
			return 0, &DeniedError{Code: CodeBudgetExhausted,
				Reason: fmt.Sprintf("mission budget used %d of %d operations", sum, l.total)}
		}
	}
	l.spent[key] = used + n
	if unlimited {
		return -1, nil
	}
	return cap - l.spent[key], nil
}

func (l *MemoryLedger) Release(missionID, server string, n int) error {
	if n <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	key := ledgerKey(missionID, server)
	if l.spent[key] < n {
		l.spent[key] = 0
		return nil
	}
	l.spent[key] -= n
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
