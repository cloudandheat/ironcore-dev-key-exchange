package mls

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"math"
	"net/netip"
	"time"

	dpservice_api "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpservice_errors "github.com/ironcore-dev/dpservice/go/dpservice-go/errors"
	"github.com/sirupsen/logrus"
)

// Every direction of a connection-pair has exactly two SA slots. The SPI of a slot is derived
// only from values, which survive a restart of the agent (VNI, underlay prefixes and the slot
// number). dpservice has no call to list its SAs, but with this a restarted agent is able to
// find all of its SAs again by probing both slots with GetSecurityAssociation. dpservice
// remains the only place, where the state of the SAs is stored.
//
// Two slots are enough, because a rekey never needs more than the current SA and its successor:
// the receiver installs the new ingress SA in the slot, which the sender does not use, the sender
// switches its egress SA over to it and afterwards the receiver deletes the old ingress SA.
const (
	numSlots            = 2
	noSlot              = -1
	saAlgorithm         = "aes-256-gcm"
	ingressReplayWindow = 1000
	dpserviceTimeout    = 5 * time.Second
)

// pairState is the SA state of one connection-pair (own host <-> peer host) within one VNI.
type pairState struct {
	egressSlot int            // slot of the egress SA towards the peer, noSlot if none
	ingress    [numSlots]bool // ingress SAs from the peer, which exist in dpservice
}

// underlayPrefix normalizes an underlay address or prefix to the network address of its /64 prefix,
// on which dpservice matches SAs. Used for the own prefix and for the prefixes of the peers, so
// both ends compute the same SPIs and keys.
func underlayPrefix(s string) (netip.Addr, error) {
	var addr netip.Addr
	if p, err := netip.ParsePrefix(s); err == nil {
		addr = p.Addr()
	} else {
		addr, err = netip.ParseAddr(s)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("invalid underlay address %q: %w", s, err)
		}
	}
	if !addr.Is6() {
		return netip.Addr{}, fmt.Errorf("underlay address %q is not IPv6", s)
	}
	return netip.PrefixFrom(addr, 64).Masked().Addr(), nil
}

// otherSlot returns the other one of the two SA slots of a direction.
func otherSlot(slot int) int {
	if slot == 0 {
		return 1
	}
	return 0
}

// slotSPIs returns the SPIs of both slots of the direction src -> dst. They depend only on values
// which survive a restart, so a restarted agent finds its SAs again. They are never below 256,
// since 1-255 are reserved (RFC 4303), and never equal to each other.
func slotSPIs(vni uint32, src, dst netip.Addr) [numSlots]uint32 {
	const spiRange = math.MaxUint32 - 255

	var spis [numSlots]uint32
	for slot := range numSlots {
		h := fnv.New32a()
		fmt.Fprintf(h, "%d|%s|%s|%d", vni, src, dst, slot)
		spis[slot] = h.Sum32()%spiRange + 256
	}
	if spis[0] == spis[1] {
		spis[1] = (spis[1]-256+1)%spiRange + 256
	}
	return spis
}

// deriveKeyMaterial derives key and salt of one direction of a connection-pair from the group
// secret of an epoch. Both directions get different key material, because both start their sequence
// numbers at 1 and the AES-GCM nonce is salt||sequence-number.
func deriveKeyMaterial(secret []byte, vni uint32, epoch uint64, src, dst netip.Addr) (key, salt []byte) {
	context := fmt.Sprintf("%d|%d|%s|%s", vni, epoch, src, dst)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("key|" + context))
	key = mac.Sum(nil)

	mac = hmac.New(sha256.New, secret)
	mac.Write([]byte("salt|" + context))
	salt = mac.Sum(nil)[:4]

	return key, salt
}

// saMeta returns the identity of the SA of a connection-pair in the given direction and slot, as
// dpservice expects it in every call. For ingress, source and destination are swapped, because
// dpservice names the addresses as seen on the wire.
func (a *AgentImpl) saMeta(vni uint32, peer netip.Addr, direction string, slot int) *dpservice_api.SecurityAssociationMeta {
	src, dst := a.ownPrefix, peer
	if direction == "ingress" {
		src, dst = peer, a.ownPrefix
	}
	return &dpservice_api.SecurityAssociationMeta{
		Vni:         vni,
		Spi:         slotSPIs(vni, src, dst)[slot],
		Direction:   direction,
		SrcUnderlay: &src,
		DstUnderlay: &dst,
	}
}

// saSpec returns the parameters of an SA of a connection-pair: algorithm, key and salt derived from
// the group secret of the epoch, extended sequence numbers and, for ingress only, the anti-replay
// window.
func (a *AgentImpl) saSpec(vni uint32, epoch uint64, secret []byte, peer netip.Addr, direction string) dpservice_api.SecurityAssociationSpec {
	src, dst := a.ownPrefix, peer
	replayWindow := uint32(0)
	if direction == "ingress" {
		src, dst = peer, a.ownPrefix
		replayWindow = ingressReplayWindow
	}
	key, salt := deriveKeyMaterial(secret, vni, epoch, src, dst)
	return dpservice_api.SecurityAssociationSpec{
		Algorithm:    saAlgorithm,
		Key:          hex.EncodeToString(key),
		Salt:         hex.EncodeToString(salt),
		ReplayWindow: replayWindow,
		Esn:          true,
	}
}

// saExists checks, whether dpservice has the SA with the given identity. dpservice has no call to
// list its SAs, so this is how the agent finds its SAs after a restart.
func (a *AgentImpl) saExists(meta *dpservice_api.SecurityAssociationMeta) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dpserviceTimeout)
	defer cancel()

	_, err := a.dpdkClient.GetSecurityAssociation(ctx, meta)
	if err == nil {
		return true, nil
	}
	if dpservice_errors.IsStatusErrorCode(err, dpservice_errors.SA_NOT_FOUND) {
		return false, nil
	}
	return false, err
}

// loadPair returns the SA state of a connection-pair: the slot of the egress SA and the slots with
// ingress SAs. If it is not known yet, which is the case after a restart of the agent, it is read
// from dpservice by probing both slots of both directions. Must be called with a.mu held.
func (a *AgentImpl) loadPair(vni uint32, peer netip.Addr) (*pairState, error) {
	if ps, ok := a.pairs[vni][peer]; ok {
		return ps, nil
	}

	ps := &pairState{egressSlot: noSlot}
	for slot := range numSlots {
		exists, err := a.saExists(a.saMeta(vni, peer, "egress", slot))
		if err != nil {
			return nil, fmt.Errorf("unable to read egress SA towards %s: %w", peer, err)
		}
		if exists {
			ps.egressSlot = slot
		}

		exists, err = a.saExists(a.saMeta(vni, peer, "ingress", slot))
		if err != nil {
			return nil, fmt.Errorf("unable to read ingress SA from %s: %w", peer, err)
		}
		ps.ingress[slot] = exists
	}

	logrus.Infof("[%s] Loaded SA state of VNI %d towards %s from dpservice: egress-slot=%d ingress-slots=%v",
		a.name, vni, peer, ps.egressSlot, ps.ingress)

	if a.pairs[vni] == nil {
		a.pairs[vni] = make(map[netip.Addr]*pairState)
	}
	a.pairs[vni][peer] = ps

	if ps.egressSlot != noSlot {
		a.setKeyReady(vni, true)
	}
	return ps, nil
}

// installIngress installs the ingress SA of the given epoch into the given slot, replacing whatever
// stale SA is still there. Used by the install phase of a rekey round. Must be called with a.mu
// held.
func (a *AgentImpl) installIngress(vni uint32, epoch uint64, secret []byte, peer netip.Addr, ps *pairState, slot int) error {
	ctx, cancel := context.WithTimeout(context.Background(), dpserviceTimeout)
	defer cancel()

	meta := a.saMeta(vni, peer, "ingress", slot)
	if ps.ingress[slot] {
		_, err := a.dpdkClient.DeleteSecurityAssociation(ctx, meta, dpservice_errors.Ignore(dpservice_errors.SA_NOT_FOUND))
		if err != nil {
			return fmt.Errorf("unable to delete stale ingress SA %s: %w", meta.GetName(), err)
		}
		ps.ingress[slot] = false
	}

	_, err := a.dpdkClient.CreateSecurityAssociation(ctx, &dpservice_api.SecurityAssociation{
		TypeMeta:                dpservice_api.TypeMeta{Kind: dpservice_api.SecurityAssociationKind},
		SecurityAssociationMeta: *meta,
		Spec:                    a.saSpec(vni, epoch, secret, peer, "ingress"),
	})
	if err != nil {
		return fmt.Errorf("unable to create ingress SA %s: %w", meta.GetName(), err)
	}
	ps.ingress[slot] = true
	return nil
}

// switchEgress replaces the egress SA towards the peer by the one of the given epoch in the other
// slot, without any gap in the protected traffic, or creates it, if there is none yet. Used by the
// switch phase of a rekey round. Must be called with a.mu held.
func (a *AgentImpl) switchEgress(vni uint32, epoch uint64, secret []byte, peer netip.Addr, ps *pairState) error {
	ctx, cancel := context.WithTimeout(context.Background(), dpserviceTimeout)
	defer cancel()

	target := 0
	if ps.egressSlot != noSlot {
		target = otherSlot(ps.egressSlot)
	}
	newMeta := a.saMeta(vni, peer, "egress", target)
	spec := a.saSpec(vni, epoch, secret, peer, "egress")

	if ps.egressSlot != noSlot {
		oldMeta := a.saMeta(vni, peer, "egress", ps.egressSlot)
		_, err := a.dpdkClient.UpdateSecurityAssociation(ctx, oldMeta, &dpservice_api.SecurityAssociationUpdate{
			NewSpi: newMeta.Spi,
			Spec:   spec,
		})
		if err != nil {
			return fmt.Errorf("unable to update egress SA %s: %w", oldMeta.GetName(), err)
		}
	} else {
		_, err := a.dpdkClient.CreateSecurityAssociation(ctx, &dpservice_api.SecurityAssociation{
			TypeMeta:                dpservice_api.TypeMeta{Kind: dpservice_api.SecurityAssociationKind},
			SecurityAssociationMeta: *newMeta,
			Spec:                    spec,
		})
		if err != nil {
			return fmt.Errorf("unable to create egress SA %s: %w", newMeta.GetName(), err)
		}
	}
	ps.egressSlot = target
	return nil
}

// deleteIngress deletes the ingress SA in the given slot, if there is one. Used by the cleanup
// phase of a rekey round and when a connection-pair is removed. Must be called with a.mu held.
func (a *AgentImpl) deleteIngress(vni uint32, peer netip.Addr, ps *pairState, slot int) error {
	if !ps.ingress[slot] {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), dpserviceTimeout)
	defer cancel()

	meta := a.saMeta(vni, peer, "ingress", slot)
	_, err := a.dpdkClient.DeleteSecurityAssociation(ctx, meta, dpservice_errors.Ignore(dpservice_errors.SA_NOT_FOUND))
	if err != nil {
		return fmt.Errorf("unable to delete ingress SA %s: %w", meta.GetName(), err)
	}
	ps.ingress[slot] = false
	return nil
}

// deletePair removes all SAs of a connection-pair from dpservice, e.g. when the peer or this host
// left the VNI. Must be called with a.mu held.
func (a *AgentImpl) deletePair(vni uint32, peer netip.Addr) error {
	ps, err := a.loadPair(vni, peer)
	if err != nil {
		return err
	}

	if ps.egressSlot != noSlot {
		ctx, cancel := context.WithTimeout(context.Background(), dpserviceTimeout)
		meta := a.saMeta(vni, peer, "egress", ps.egressSlot)
		_, err := a.dpdkClient.DeleteSecurityAssociation(ctx, meta, dpservice_errors.Ignore(dpservice_errors.SA_NOT_FOUND))
		cancel()
		if err != nil {
			return fmt.Errorf("unable to delete egress SA %s: %w", meta.GetName(), err)
		}
		ps.egressSlot = noSlot
	}
	for slot := range numSlots {
		if err := a.deleteIngress(vni, peer, ps, slot); err != nil {
			return err
		}
	}

	delete(a.pairs[vni], peer)
	logrus.Infof("[%s] Deleted all SAs of VNI %d towards %s", a.name, vni, peer)
	return nil
}

// knownPeers returns all peers, towards which SAs of the VNI may exist: the ones already known and
// the next-hops of the routes of the VNI in dpservice. Used to clean up all SAs of a VNI, even when
// a restart emptied the local state. Must be called with a.mu held.
func (a *AgentImpl) knownPeers(vni uint32) []netip.Addr {
	seen := make(map[netip.Addr]bool)
	var peers []netip.Addr
	for peer := range a.pairs[vni] {
		seen[peer] = true
		peers = append(peers, peer)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dpserviceTimeout)
	defer cancel()

	routes, err := a.dpdkClient.ListRoutes(ctx, vni)
	if err != nil {
		logrus.Warnf("[%s] Unable to list routes of VNI %d: %v", a.name, vni, err)
		return peers
	}
	for _, route := range routes.Items {
		if route.Spec.NextHop == nil || route.Spec.NextHop.IP == nil {
			continue
		}
		peer, err := underlayPrefix(route.Spec.NextHop.IP.String())
		if err != nil || peer == a.ownPrefix || seen[peer] {
			continue
		}
		seen[peer] = true
		peers = append(peers, peer)
	}
	return peers
}

// encryptedVNIs returns all VNIs, which have encrypting interfaces in dpservice. These are the VNIs
// the agent was subscribed to before it restarted.
func (a *AgentImpl) encryptedVNIs() ([]uint32, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dpserviceTimeout)
	defer cancel()

	ifaces, err := a.dpdkClient.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}

	seen := make(map[uint32]bool)
	var vnis []uint32
	for _, iface := range ifaces.Items {
		if iface.Spec.Encrypt && !seen[iface.Spec.VNI] {
			seen[iface.Spec.VNI] = true
			vnis = append(vnis, iface.Spec.VNI)
		}
	}
	return vnis, nil
}

// underlayFromDpservice returns the underlay prefix of this host, taken from the interfaces in
// dpservice. Used by the self-initialization after a restart.
func (a *AgentImpl) underlayFromDpservice() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dpserviceTimeout)
	defer cancel()

	ifaces, err := a.dpdkClient.ListInterfaces(ctx)
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces.Items {
		if iface.Spec.UnderlayRoute != nil {
			return netip.PrefixFrom(*iface.Spec.UnderlayRoute, 64).Masked().String(), nil
		}
	}
	return "", fmt.Errorf("no interface with underlay route found")
}

// markAllInterfacesAsEncrypted enables encryption on all interfaces of the VNI in dpservice. It is
// a workaround until metalnet does this itself, and is called once the egress SAs of the VNI are in
// place.
func (a *AgentImpl) markAllInterfacesAsEncrypted(vni uint32) {
	// Workaround for the moment to enable encryption for all interfaces of the VNI
	// TODO: handle by metalnet network-interface controller
	ctx, cancel := context.WithTimeout(context.Background(), dpserviceTimeout)
	defer cancel()

	interfaceList, err := a.dpdkClient.ListInterfaces(ctx)
	if err != nil {
		logrus.Errorf("[%s] Error listing interfaces: %v", a.name, err)
		return
	}
	for _, iface := range interfaceList.Items {
		if iface.Spec.VNI == vni && !iface.Spec.Encrypt {
			_, err := a.dpdkClient.EnableInterfaceEncryption(ctx, iface.ID)
			if err != nil {
				logrus.Errorf("[%s] Error enabling encryption of interface %s: %v", a.name, iface.ID, err)
			}
		}
	}
}
