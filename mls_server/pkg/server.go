// The MLS server: delivery service and coordinator for the agents. This file holds the server
// itself, its HTTP wiring and the periodic housekeeping.
package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// The server holds no persistent state. Everything it knows is rebuilt from the agents, when
// they register and subscribe again after it restarted. To make them notice a restart, every
// response carries the boot-ID of this server instance.
const BootIDHeader = "X-Mls-Server-Boot-Id"

const (
	// a membership operation or a rekey round, which did not complete within this time, is
	// considered stalled (e.g. because a member is down) and does not block further progress
	stallTimeout = 20 * time.Second
	// an agent, which did not poll within this time, is considered dead
	livenessTimeout = 45 * time.Second
	maxOpRetries    = 3
	// interval of the regular key rotation, can be overridden by MLS_KEY_ROTATION_INTERVAL
	defaultKeyRotationInterval = 60 * time.Minute
)

type ServerImpl struct {
	mu          sync.Mutex
	bootID      string
	nextOpID    uint64
	mailboxes   map[string]chan Envelope
	keyPackages map[string][][]byte
	lastSeen    map[string]time.Time
	groups      map[uint32]*group
}

// NewServer creates a server with empty state and a random boot-ID, by which the agents detect a
// restart.
func NewServer() *ServerImpl {
	id := make([]byte, 8)
	rand.Read(id)

	return &ServerImpl{
		bootID:      hex.EncodeToString(id),
		mailboxes:   make(map[string]chan Envelope),
		keyPackages: make(map[string][][]byte),
		lastSeen:    make(map[string]time.Time),
		groups:      make(map[uint32]*group),
	}
}

// isAlive reports, whether the agent polled recently. Used to prefer live members, when a new
// committer has to be chosen. Must be called with s.mu held.
func (s *ServerImpl) isAlive(user string) bool {
	return time.Since(s.lastSeen[user]) < livenessTimeout
}

// queryVNI reads a VNI from a query parameter of a request.
func queryVNI(r *http.Request, key string) uint32 {
	v, _ := strconv.ParseUint(r.URL.Query().Get(key), 10, 32)
	return uint32(v)
}

// queryUint64 reads an unsigned number, e.g. an epoch, from a query parameter of a request.
func queryUint64(r *http.Request, key string) uint64 {
	v, _ := strconv.ParseUint(r.URL.Query().Get(key), 10, 64)
	return v
}

// withBootID wraps an HTTP handler: it adds the boot-ID header to every response, so agents detect
// a restart of the server, and records the time the calling agent was last seen, for the liveness
// check.
func (s *ServerImpl) withBootID(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(BootIDHeader, s.bootID)
		if user := r.URL.Query().Get("user"); user != "" {
			s.mu.Lock()
			s.lastSeen[user] = time.Now()
			s.mu.Unlock()
		}
		h(w, r)
	}
}

// housekeeping runs every 2 seconds and keeps all groups moving, even without new requests: it
// replaces dead committers and lets progress resolve stalled rounds and operations.
func (s *ServerImpl) housekeeping() {
	ticker := time.NewTicker(2 * time.Second)
	for range ticker.C {
		s.mu.Lock()
		for _, g := range s.groups {
			if g.committer != "" && !s.isAlive(g.committer) && len(g.members) > 1 {
				if c := s.pickCommitter(g, g.committer); c != "" && s.isAlive(c) {
					s.setCommitter(g, c)
				}
			}
			s.progress(g)
		}
		s.mu.Unlock()
	}
}

// keyRotationInterval returns the interval of the regular key rotation: MLS_KEY_ROTATION_INTERVAL
// as a Go duration (e.g. "30m"), or 60 minutes, if it is not set or invalid.
func keyRotationInterval() time.Duration {
	if v := os.Getenv("MLS_KEY_ROTATION_INTERVAL"); v != "" {
		interval, err := time.ParseDuration(v)
		if err == nil && interval > 0 {
			return interval
		}
		logrus.Errorf("[MLS-Broker] Invalid MLS_KEY_ROTATION_INTERVAL %q, using %s", v, defaultKeyRotationInterval)
	}
	return defaultKeyRotationInterval
}

// startKeyRotationLoop rotates the keys of every group with at least two members in the given
// interval. It queues a self-update for the committer, whose commit moves the group to a new epoch,
// and the rekey round of that epoch replaces the SAs of all connection-pairs with new keys. A group,
// which still has a rotation queued, e.g. because it is stalled by a dead member, gets no second
// one.
func (s *ServerImpl) startKeyRotationLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		s.mu.Lock()
		for _, g := range s.groups {
			if len(g.members) < 2 || g.hasQueued(OpUpdate) {
				continue
			}
			logrus.Infof("[MLS-Broker] Triggering key rotation for VNI %d", g.vni)
			s.enqueue(g, OpUpdate, "")
			s.progress(g)
		}
		s.mu.Unlock()
	}
}

// Start registers the HTTP endpoints for the agents, starts the housekeeping and the key rotation
// and serves on the given address. It blocks for the whole lifetime of the server.
func (s *ServerImpl) Start(port string) error {
	logrus.Infof("[MLS-Broker] start MLS server with boot-id %s", s.bootID)

	mux := http.NewServeMux()
	mux.HandleFunc("/register", s.withBootID(s.registerHandler))
	mux.HandleFunc("/send", s.withBootID(s.sendHandler))
	mux.HandleFunc("/poll", s.withBootID(s.pollHandler))
	mux.HandleFunc("/upload_kp", s.withBootID(s.uploadKP))
	mux.HandleFunc("/get_kp", s.withBootID(s.getKP))
	mux.HandleFunc("/subscribe", s.withBootID(s.handleSubscribe))
	mux.HandleFunc("/unsubscribe", s.withBootID(s.handleUnsubscribe))
	mux.HandleFunc("/op_done", s.withBootID(s.opDoneHandler))
	mux.HandleFunc("/ready", s.withBootID(s.readyHandler))
	mux.HandleFunc("/round_ack", s.withBootID(s.roundAckHandler))

	go s.housekeeping()

	interval := keyRotationInterval()
	logrus.Infof("[MLS-Broker] rotating keys every %s", interval)
	go s.startKeyRotationLoop(interval)

	return http.ListenAndServe(port, mux)
}
