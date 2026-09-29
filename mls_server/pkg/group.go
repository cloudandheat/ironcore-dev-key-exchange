// Group membership: subscriptions, the queue of membership operations and the committer, which
// executes them.
package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
)

type group struct {
	vni         uint32
	subscribers map[string]string // user -> ip
	members     map[string]bool   // members of the MLS group, as reported by the committer
	committer   string
	epoch       uint64
	epochSince  time.Time
	ready       map[uint64]map[string]bool // members, which reached an epoch
	queue       []*Op
	inflight    *Op
	inflightAt  time.Time
	round       *round
}

// enqueue queues a membership operation for the committer of the group. An operation for a user
// replaces any older one still queued for the same user, because only the latest intent matters.
// Must be called with s.mu held.
func (s *ServerImpl) enqueue(g *group, kind, user string) {
	var queue []*Op
	for _, op := range g.queue {
		if user == "" || op.User != user {
			queue = append(queue, op)
		}
	}
	s.nextOpID++
	g.queue = append(queue, &Op{ID: s.nextOpID, Kind: kind, User: user})
}

// hasQueued reports, whether an operation of the given kind is queued or in flight for the group.
// Must be called with s.mu held.
func (g *group) hasQueued(kind string) bool {
	if g.inflight != nil && g.inflight.Kind == kind {
		return true
	}
	for _, op := range g.queue {
		if op.Kind == kind {
			return true
		}
	}
	return false
}

// pickCommitter chooses a new committer among the members of the group, except the given one, and
// prefers members which are alive. Returns an empty string, if there is no candidate. Must be
// called with s.mu held.
func (s *ServerImpl) pickCommitter(g *group, exclude string) string {
	var candidates []string
	for member := range g.members {
		if member != exclude {
			candidates = append(candidates, member)
		}
	}
	sort.Strings(candidates)
	for _, c := range candidates {
		if s.isAlive(c) {
			return c
		}
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return ""
}

// setCommitter makes another member the committer of the group, e.g. because the old one restarted,
// died or left. An operation, which was handed to the old committer and not yet finished, is handed
// to the new one. Must be called with s.mu held.
func (s *ServerImpl) setCommitter(g *group, committer string) {
	if g.committer == committer {
		return
	}
	logrus.Infof("[MLS-Broker] VNI %d: committer changes from '%s' to '%s'", g.vni, g.committer, committer)
	g.committer = committer
	if g.inflight != nil {
		g.queue = append([]*Op{g.inflight}, g.queue...)
		g.inflight = nil
	}
}

// resetGroup replaces the group by a new one, which the given user creates, e.g. after the server
// restarted or when the only member lost its state. All other subscribers have to join it again and
// are queued for it. Their SAs stay untouched until they joined and the connection-pairs are
// rekeyed by a round. Must be called with s.mu held.
func (s *ServerImpl) resetGroup(g *group, creator string) {
	logrus.Infof("[MLS-Broker] VNI %d: '%s' creates a new group", g.vni, creator)
	g.members = map[string]bool{creator: true}
	g.committer = creator
	g.epoch = 0
	g.epochSince = time.Now()
	g.ready = make(map[uint64]map[string]bool)
	g.round = nil
	g.inflight = nil
	g.queue = nil
	for user := range g.subscribers {
		if user != creator {
			s.enqueue(g, OpAdd, user)
		}
	}
}

// handleSubscribe handles /subscribe, by which an agent joins the group of a VNI, also again after
// a restart of itself or of the server. The answer tells the agent what to do: "member" if it is
// still a member with valid state, "created" if it has to create the group, or "joining" if it has
// to wait for being (re-)added by the committer, for which an operation is queued.
func (s *ServerImpl) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	vni := queryVNI(r, "id")
	ip := r.URL.Query().Get("ip")
	hasGroup := r.URL.Query().Get("has_group") == "1"

	s.mu.Lock()
	defer s.mu.Unlock()

	g := s.groups[vni]
	if g == nil {
		g = &group{
			vni:         vni,
			subscribers: make(map[string]string),
		}
		s.groups[vni] = g
	}
	_, wasSubscribed := g.subscribers[user]
	g.subscribers[user] = ip

	status := "joining"
	switch {
	case wasSubscribed && hasGroup && g.members[user]:
		// repeated subscribe of an agent, which still has its state
		status = "member"
	case len(g.members) == 0 || (len(g.members) == 1 && g.members[user]):
		// no group yet, or the only member lost its state
		s.resetGroup(g, user)
		status = "created"
	default:
		if g.committer == user {
			s.setCommitter(g, s.pickCommitter(g, user))
		}
		if g.members[user] {
			// the agent lost its state, but its old leaf is still in the group
			s.enqueue(g, OpReadd, user)
		} else {
			s.enqueue(g, OpAdd, user)
		}
	}

	logrus.Infof("[MLS-Broker] '%s' subscribed to VNI %d (has_group=%t): %s", user, vni, hasGroup, status)
	s.progress(g)

	json.NewEncoder(w).Encode(BrokerResp{Status: status, VNI: vni})
}

// handleUnsubscribe handles /unsubscribe, by which an agent leaves the group of a VNI. The
// remaining subscribers are told to delete their SAs towards it and its removal from the MLS group
// is queued. A group without subscribers is dropped.
func (s *ServerImpl) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	vni := queryVNI(r, "id")

	s.mu.Lock()
	defer s.mu.Unlock()

	g := s.groups[vni]
	if g == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	ip, wasSubscribed := g.subscribers[user]
	delete(g.subscribers, user)

	if wasSubscribed {
		// the peer is gone intentionally, so its SAs can be removed right away
		data, _ := json.Marshal(PeerLeftMsg{User: user, IP: ip})
		for sub := range g.subscribers {
			s.deliver(sub, Envelope{Type: MsgPeerLeft, From: "broker", VNI: vni, Data: data})
		}
	}

	if len(g.subscribers) == 0 {
		logrus.Infof("[MLS-Broker] VNI %d has no subscribers anymore, dropping group", vni)
		delete(s.groups, vni)
		w.WriteHeader(http.StatusOK)
		return
	}

	if g.members[user] {
		if g.committer == user {
			s.setCommitter(g, s.pickCommitter(g, user))
		}
		logrus.Infof("[MLS-Broker] '%s' unsubscribed from VNI %d, queue removal", user, vni)
		s.enqueue(g, OpRemove, user)
	} else {
		// drop any pending add for it
		var queue []*Op
		for _, op := range g.queue {
			if op.User != user {
				queue = append(queue, op)
			}
		}
		g.queue = queue
	}

	s.progress(g)
	w.WriteHeader(http.StatusOK)
}

// opDoneHandler handles /op_done, by which the committer reports the result of a membership
// operation, together with the resulting epoch and members of the group. Failed operations are
// retried a few times.
func (s *ServerImpl) opDoneHandler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	vni := queryVNI(r, "vni")

	var res OpResult
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	g := s.groups[vni]
	// A report of a former committer is still the truth about the group, if it moved the epoch.
	if g == nil || (g.committer != user && res.Epoch <= g.epoch) {
		w.WriteHeader(http.StatusOK)
		return
	}

	op := g.inflight
	if op != nil && op.ID == res.ID {
		g.inflight = nil
		if res.Failed {
			op.retries++
			if op.retries < maxOpRetries {
				logrus.Warnf("[MLS-Broker] VNI %d: op %s(%s) failed, retry later", vni, op.Kind, op.User)
				g.queue = append(g.queue, op)
			} else {
				logrus.Errorf("[MLS-Broker] VNI %d: op %s(%s) failed too often, giving up", vni, op.Kind, op.User)
			}
		}
	}

	// without members the committer has no usable group state, so there is nothing to learn
	if len(res.Members) > 0 {
		s.setEpoch(g, res.Epoch, res.Members)
	}

	s.progress(g)
	w.WriteHeader(http.StatusOK)
}

// setEpoch records a new epoch and member list of the group, as reported by the committer, and
// forgets ready-reports of older epochs. Must be called with s.mu held.
func (s *ServerImpl) setEpoch(g *group, epoch uint64, members []string) {
	g.members = make(map[string]bool)
	for _, m := range members {
		g.members[m] = true
	}
	if epoch != g.epoch {
		g.epoch = epoch
		g.epochSince = time.Now()
	}
	for e := range g.ready {
		if e < epoch {
			delete(g.ready, e)
		}
	}
	logrus.Infof("[MLS-Broker] VNI %d is at epoch %d with members %v", g.vni, epoch, members)
}

// progress moves a group forward and is called after every change of it: it starts the rekey round
// of the current epoch as soon as all members reached it, and hands the next membership operation
// to the committer as soon as the group is idle. Rounds and operations stuck because of a dead
// member do not block forever. Must be called with s.mu held.
func (s *ServerImpl) progress(g *group) {
	if g.round == nil || g.round.epoch != g.epoch {
		allReady := len(g.members) > 0
		for m := range g.members {
			if !g.ready[g.epoch][m] {
				allReady = false
				break
			}
		}
		if allReady {
			s.startRound(g)
		}
	}

	if g.inflight != nil {
		if time.Since(g.inflightAt) > stallTimeout && !s.isAlive(g.committer) {
			s.setCommitter(g, s.pickCommitter(g, g.committer))
		} else {
			return
		}
	}

	if len(g.queue) == 0 || g.committer == "" {
		return
	}

	idle := false
	switch {
	case g.round != nil && g.round.epoch == g.epoch:
		idle = g.round.phase == phaseDone || time.Since(g.round.updated) > stallTimeout
	default:
		idle = time.Since(g.epochSince) > stallTimeout
	}
	if !idle {
		return
	}

	op := g.queue[0]
	g.queue = g.queue[1:]
	g.inflight = op
	g.inflightAt = time.Now()

	logrus.Infof("[MLS-Broker] VNI %d: mandating '%s' to execute %s(%s)", g.vni, g.committer, op.Kind, op.User)
	data, _ := json.Marshal(op)
	s.deliver(g.committer, Envelope{Type: MsgOp, From: "broker", VNI: g.vni, Epoch: g.epoch, Data: data})
}
