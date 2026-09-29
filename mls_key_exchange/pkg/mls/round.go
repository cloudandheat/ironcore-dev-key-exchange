// Rekey rounds: the agent's side of rekeying all connection-pairs of a group make-before-break.
package mls

import (
	"encoding/json"
	"net/netip"

	"github.com/sirupsen/logrus"
)

// roundState is the state of the rekey round of the current epoch of a group. The group secret
// is exported once, when the epoch is reached, because the MLS group may already have moved on
// to the next epoch, while the round is still running.
type roundState struct {
	epoch     uint64
	secret    []byte
	peers     map[string]netip.Addr // participating peers of the round
	installed map[string]int        // slot of the new ingress SA per peer
}

// handleRound dispatches a message of a rekey round to the handler of its phase. Messages of a
// round, which does not belong to the current epoch of the group, are ignored, so an outdated round
// never touches any SA.
func (a *AgentImpl) handleRound(vni uint32, msgType string, msg RoundMsg) {
	r := a.rounds[vni]
	if r == nil || r.epoch != msg.Epoch {
		// round of an outdated epoch, its SAs are never touched
		logrus.Infof("[%s] Ignoring %s of outdated epoch %d on VNI %d", a.name, msgType, msg.Epoch, vni)
		return
	}

	switch msgType {
	case msgRoundPrepare:
		a.roundPrepare(vni, r, msg)
	case msgRoundInstall:
		a.roundInstall(vni, r, msg)
	case msgRoundSwitch:
		a.roundSwitch(vni, r)
	case msgRoundCleanup:
		a.roundCleanup(vni, r)
	}
}

// roundPrepare handles the first phase of a rekey round: it reports the slot of the egress SA
// towards every peer of the round to the server. After a restart the slots are read from dpservice.
// If they can not be read, no ack is sent, which stalls the round and leaves all SAs untouched.
func (a *AgentImpl) roundPrepare(vni uint32, r *roundState, msg RoundMsg) {
	r.peers = make(map[string]netip.Addr)
	r.installed = make(map[string]int)

	slots := make(map[string]int)
	for _, p := range msg.Peers {
		if p.IP == "" {
			continue
		}
		peer, err := underlayPrefix(p.IP)
		if err != nil {
			logrus.Errorf("[%s] Peer %s: %v", a.name, p.User, err)
			continue
		}
		ps, err := a.loadPair(vni, peer)
		if err != nil {
			// without an ack the round stalls, which leaves all SAs untouched
			logrus.Errorf("[%s] %v", a.name, err)
			return
		}
		r.peers[p.User] = peer
		slots[p.User] = ps.egressSlot
	}

	body, _ := json.Marshal(slots)
	a.postRoundAck(vni, r.epoch, "prepare", body)
}

// roundInstall handles the second phase of a rekey round: it installs a new ingress SA from every
// peer in the slot, which the peer does not use for sending, so the peer can switch to it at any
// time.
func (a *AgentImpl) roundInstall(vni uint32, r *roundState, msg RoundMsg) {
	for _, p := range msg.Peers {
		peer, ok := r.peers[p.User]
		if !ok {
			continue
		}
		ps, err := a.loadPair(vni, peer)
		if err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
			return
		}

		slot := 0
		if p.Slot != noSlot {
			slot = otherSlot(p.Slot)
		}
		if err := a.installIngress(vni, r.epoch, r.secret, peer, ps, slot); err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
			return
		}
		r.installed[p.User] = slot
		logrus.Infof("[%s] Installed ingress SA of VNI %d epoch %d from %s in slot %d", a.name, vni, r.epoch, peer, slot)
	}

	a.postRoundAck(vni, r.epoch, "install", nil)
}

// roundSwitch handles the third phase of a rekey round: it replaces the egress SA towards every
// peer by the new one, now that all peers are able to decrypt with it, and marks the key of the VNI
// as ready.
func (a *AgentImpl) roundSwitch(vni uint32, r *roundState) {
	for user, peer := range r.peers {
		ps, err := a.loadPair(vni, peer)
		if err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
			return
		}
		if err := a.switchEgress(vni, r.epoch, r.secret, peer, ps); err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
			return
		}
		logrus.Infof("[%s] Switched egress SA of VNI %d towards %s (%s) to slot %d", a.name, vni, user, peer, ps.egressSlot)
	}

	// Workaround. TODO: remove and handle in metalnet
	a.markAllInterfacesAsEncrypted(vni)
	a.setKeyReady(vni, true)

	a.postRoundAck(vni, r.epoch, "switch", nil)
}

// roundCleanup handles the last phase of a rekey round: it deletes the old ingress SAs, now that no
// peer uses them anymore.
func (a *AgentImpl) roundCleanup(vni uint32, r *roundState) {
	for user, slot := range r.installed {
		peer := r.peers[user]
		ps, err := a.loadPair(vni, peer)
		if err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
			continue
		}
		if err := a.deleteIngress(vni, peer, ps, otherSlot(slot)); err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
		}
	}
	logrus.Infof("[%s] Rekey of VNI %d to epoch %d completed", a.name, vni, r.epoch)
}
