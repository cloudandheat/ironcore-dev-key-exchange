// Rekey rounds: after every epoch change all connection-pairs of a group are rekeyed
// make-before-break, coordinated phase by phase.
package server

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
)

// Rekey round phases. A round rekeys every connection-pair within a group, after the MLS group
// moved to a new epoch, following make-before-break:
//
//	prepare: every member reports the egress SA slot it currently uses towards each peer
//	install: every member installs its new ingress SAs in the slot, which is not in use by the peer
//	switch:  every member replaces its egress SAs by the new ones
//	cleanup: every member deletes its old ingress SAs
//
// Each phase starts only when all members completed the previous one. If a round stalls, the old
// SAs stay untouched, so every connection-pair stays in a consistent state.
const (
	phasePrepare = "prepare"
	phaseInstall = "install"
	phaseSwitch  = "switch"
	phaseDone    = "done"
)

type round struct {
	epoch        uint64
	phase        string
	participants []string
	acks         map[string]bool
	// sender -> receiver -> egress slot of the sender towards the receiver
	slots   map[string]map[string]int
	updated time.Time
}

// readyHandler handles /ready, by which every member reports, that it reached a new epoch. As soon
// as all members did, the rekey round of the epoch starts.
func (s *ServerImpl) readyHandler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	vni := queryVNI(r, "vni")
	epoch := queryUint64(r, "epoch")

	s.mu.Lock()
	defer s.mu.Unlock()

	g := s.groups[vni]
	if g == nil || epoch < g.epoch {
		w.WriteHeader(http.StatusOK)
		return
	}
	if g.ready == nil {
		g.ready = make(map[uint64]map[string]bool)
	}
	if g.ready[epoch] == nil {
		g.ready[epoch] = make(map[string]bool)
	}
	g.ready[epoch][user] = true

	s.progress(g)
	w.WriteHeader(http.StatusOK)
}

// roundAckHandler handles /round_ack, by which every member reports, that it completed a phase of
// the current rekey round. As soon as all participants did, the round moves on to the next phase.
// Acks of outdated rounds are ignored.
func (s *ServerImpl) roundAckHandler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	vni := queryVNI(r, "vni")
	epoch := queryUint64(r, "epoch")
	phase := r.URL.Query().Get("phase")

	var slots map[string]int
	if phase == phasePrepare {
		json.NewDecoder(r.Body).Decode(&slots)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	g := s.groups[vni]
	if g == nil || g.round == nil || g.round.epoch != epoch || g.round.phase != phase {
		// ack of an outdated round
		w.WriteHeader(http.StatusOK)
		return
	}

	rd := g.round
	rd.acks[user] = true
	if phase == phasePrepare {
		rd.slots[user] = slots
	}

	for _, p := range rd.participants {
		if !rd.acks[p] {
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	s.advanceRound(g)
	s.progress(g)
	w.WriteHeader(http.StatusOK)
}

// roundPeers returns all participants of the round, except the given one, including the slots of
// their egress SAs towards the given one. Must be called with s.mu held.
func (s *ServerImpl) roundPeers(g *group, receiver string) []RoundPeer {
	var peers []RoundPeer
	for _, p := range g.round.participants {
		if p == receiver {
			continue
		}
		slot := -1
		if slots, ok := g.round.slots[p]; ok {
			if v, ok := slots[receiver]; ok {
				slot = v
			}
		}
		peers = append(peers, RoundPeer{User: p, IP: g.subscribers[p], Slot: slot})
	}
	return peers
}

// advanceRound moves the round to its next phase and tells all participants to execute it, once all
// of them acked the current phase. Must be called with s.mu held.
func (s *ServerImpl) advanceRound(g *group) {
	rd := g.round
	var next, msgType string
	switch rd.phase {
	case phasePrepare:
		next, msgType = phaseInstall, MsgRoundInstall
	case phaseInstall:
		next, msgType = phaseSwitch, MsgRoundSwitch
	case phaseSwitch:
		next, msgType = phaseDone, MsgRoundCleanup
	default:
		return
	}

	logrus.Infof("[MLS-Broker] VNI %d epoch %d: round phase %s completed", g.vni, rd.epoch, rd.phase)
	rd.phase = next
	rd.acks = make(map[string]bool)
	rd.updated = time.Now()

	for _, p := range rd.participants {
		msg := RoundMsg{Epoch: rd.epoch}
		if msgType == MsgRoundInstall {
			msg.Peers = s.roundPeers(g, p)
		}
		data, _ := json.Marshal(msg)
		s.deliver(p, Envelope{Type: msgType, From: "broker", VNI: g.vni, Epoch: rd.epoch, Data: data})
	}
}

// startRound starts the rekey round for the current epoch of the group with all its members,
// beginning with the prepare phase. A group with less than two members has nothing to rekey, so its
// round is done right away. Must be called with s.mu held.
func (s *ServerImpl) startRound(g *group) {
	var participants []string
	for m := range g.members {
		participants = append(participants, m)
	}
	sort.Strings(participants)

	rd := &round{
		epoch:        g.epoch,
		phase:        phasePrepare,
		participants: participants,
		acks:         make(map[string]bool),
		slots:        make(map[string]map[string]int),
		updated:      time.Now(),
	}
	g.round = rd

	if len(participants) < 2 {
		// nothing to rekey
		rd.phase = phaseDone
		return
	}

	logrus.Infof("[MLS-Broker] VNI %d epoch %d: starting rekey round for %v", g.vni, g.epoch, participants)
	for _, p := range participants {
		data, _ := json.Marshal(RoundMsg{Epoch: rd.epoch, Peers: s.roundPeers(g, p)})
		s.deliver(p, Envelope{Type: MsgRoundPrepare, From: "broker", VNI: g.vni, Epoch: rd.epoch, Data: data})
	}
}
