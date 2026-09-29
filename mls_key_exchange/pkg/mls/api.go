// gRPC API used by metalnet.
package mls

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"

	pb "github.com/cloudandheat/ironcore-dev-key-exchange/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// initLocked (re-)initializes the agent for the host with the given underlay prefix. It creates a
// new MLS credential, registers at the MLS server, recovers the subscribed VNIs from the encrypting
// interfaces in dpservice, subscribes all of them and starts the poll loop. Used by Init and by the
// self-initialization. Must be called with a.mu held.
//
// The identity of the agent within the MLS groups is the underlay prefix of its host. There is
// exactly one dpservice and one agent per host, so it is unique, it survives restarts and it is
// available from dpservice, which lets a restarted agent come back under the same identity without
// any help from metalnet.
func (a *AgentImpl) initLocked(prefix string) error {
	ownPrefix, err := underlayPrefix(prefix)
	if err != nil {
		return err
	}
	name := netip.PrefixFrom(ownPrefix, 64).String()

	if a.grpcClient == nil {
		conn, err := grpc.NewClient(os.Getenv("RUST_GRPC_URL"), grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return fmt.Errorf("failed to connect to grpc: %v", err)
		}
		a.grpcClient = pb.NewMlsServiceClient(conn)
	}

	if a.name != "" {
		// a new identity, so all local MLS state is useless
		for vni := range a.subscribed {
			a.dropGroupLocked(vni)
		}
	}

	a.name = name
	a.serverURL = os.Getenv("MLS_SERVER_ADDRESS")
	a.clientPrefix = name
	a.ownPrefix = ownPrefix

	_, err = a.grpcClient.GenerateCredential(context.Background(), &pb.GenerateReq{ClientId: name})
	if err != nil {
		a.name = ""
		return fmt.Errorf("[%s] Failed to generate credential: %v", name, err)
	}

	if err := a.registerLocked(); err != nil {
		a.name = ""
		return fmt.Errorf("[%s] Failed to register at MLS server: %v", name, err)
	}

	// After a restart the VNIs this agent was subscribed to are the ones with encrypting
	// interfaces in dpservice. Subscribing them again brings the agent back into their groups.
	vnis, err := a.encryptedVNIs()
	if err != nil {
		logrus.Warnf("[%s] Unable to recover VNIs from dpservice: %v", name, err)
	}
	for _, vni := range vnis {
		if !a.subscribed[vni] {
			logrus.Infof("[%s] Recovered VNI %d from dpservice", name, vni)
			a.subscribed[vni] = true
		}
	}
	for vni := range a.subscribed {
		if err := a.subscribeLocked(vni); err != nil {
			logrus.Errorf("[%s] Failed to subscribe VNI %d: %v", name, vni, err)
		}
	}

	a.startListener()
	return nil
}

// Init is called by metalnet to initialize the agent with the underlay prefix of its host. The
// client name is only logged, the identity of the agent is its underlay prefix. Calling it again
// for the same prefix, or after the agent already initialized itself from dpservice, does nothing.
func (a *AgentImpl) Init(ctx context.Context, req *pb.AgentInitReq) (*pb.AgentEmpty, error) {
	logrus.Infof("Init Agent %s with prefix %s", req.ClientName, req.ClientPrefix)

	a.mu.Lock()
	defer a.mu.Unlock()

	ownPrefix, err := underlayPrefix(req.ClientPrefix)
	if err != nil {
		return nil, err
	}
	if a.name == netip.PrefixFrom(ownPrefix, 64).String() {
		// already initialized, e.g. by auto-init or an earlier call
		return &pb.AgentEmpty{}, nil
	}

	if err := a.initLocked(req.ClientPrefix); err != nil {
		return nil, err
	}
	return &pb.AgentEmpty{}, nil
}

// subscribeLocked (re-)subscribes the agent to the group of a VNI at the MLS server and acts on its
// answer: "member" keeps the local group, "created" creates a new group with this agent as its only
// member and anything else drops the local group state and waits to be (re-)added by the committer.
// The SAs in dpservice are not touched, they keep working until the next rekey round replaces them.
// Must be called with a.mu held.
func (a *AgentImpl) subscribeLocked(vni uint32) error {
	info, err := a.groupInfo(vni)
	if err != nil {
		return fmt.Errorf("unable to get local group state: %w", err)
	}
	hasGroup := "0"
	if info.Exists {
		hasGroup = "1"
	}

	resp, err := a.serverRequest(http.MethodGet, "/subscribe", url.Values{
		"user":      {a.name},
		"id":        {strconv.FormatUint(uint64(vni), 10)},
		"ip":        {a.clientPrefix},
		"has_group": {hasGroup},
	}, nil)
	if err != nil {
		return fmt.Errorf("broker subscribe error: %v", err)
	}
	defer resp.Body.Close()

	var bResp struct {
		Status string `json:"status"`
		VNI    uint32 `json:"vni"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&bResp); err != nil {
		return fmt.Errorf("invalid subscribe response: %w", err)
	}

	switch bResp.Status {
	case "member":
		logrus.Infof("[%s] Still member of VNI %d", a.name, vni)
	case "created":
		logrus.Infof("[%s] Subscribed. Creating group for VNI %d", a.name, vni)
		a.dropGroupLocked(vni)
		_, err := a.grpcClient.CreateGroup(context.Background(), &pb.CreateGroupReq{ClientId: a.name, GroupId: groupID(vni)})
		if err != nil {
			return fmt.Errorf("failed to create group for VNI %d: %w", vni, err)
		}
		info, err := a.groupInfo(vni)
		if err != nil {
			return err
		}
		a.reachedEpochLocked(vni, info.Epoch)
	default:
		// Any old group state is useless, the agent is (re-)added to the group of the server.
		// Until that happened and the connection-pairs are rekeyed, the old SAs keep working.
		logrus.Infof("[%s] Subscribed to VNI %d, waiting for invite", a.name, vni)
		if info.Exists {
			a.dropGroupLocked(vni)
		}
	}
	return nil
}

// Subscribe is called by metalnet to add this host to the encrypted network of a VNI. It is
// idempotent, subscribing a VNI the agent is already a member of changes nothing.
func (a *AgentImpl) Subscribe(ctx context.Context, req *pb.AgentSubscribeReq) (*pb.AgentEmpty, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	logrus.Infof("[%s] Subscribe VNI: %d", a.name, req.Vni)
	if a.name == "" {
		return nil, fmt.Errorf("agent not initialized")
	}

	a.subscribed[req.Vni] = true
	if err := a.subscribeLocked(req.Vni); err != nil {
		return nil, err
	}
	return &pb.AgentEmpty{}, nil
}

// Unsubscribe is called by metalnet to remove this host from the encrypted network of a VNI. It
// unsubscribes at the server, which lets the peers delete their SAs towards this host, drops the
// local group state and deletes all SAs of the VNI from dpservice.
func (a *AgentImpl) Unsubscribe(ctx context.Context, req *pb.AgentUnsubscribeReq) (*pb.AgentEmpty, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	vni := req.Vni
	logrus.Infof("[%s] Unsubscribe VNI: %d", a.name, vni)

	err := a.serverPost("/unsubscribe", url.Values{"user": {a.name}, "id": {strconv.FormatUint(uint64(vni), 10)}}, nil)
	if err != nil {
		logrus.Errorf("[%s] Failed to unsubscribe VNI %d at server: %v", a.name, vni, err)
	}

	delete(a.subscribed, vni)
	a.dropGroupLocked(vni)
	a.setKeyReady(vni, false)

	for _, peer := range a.knownPeers(vni) {
		if err := a.deletePair(vni, peer); err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
		}
	}
	delete(a.pairs, vni)

	return &pb.AgentEmpty{}, nil
}

// IsKeyReady is called by metalnet to check, whether the SAs of a VNI are in place, so that the
// interfaces of the VNI can send encrypted traffic.
func (a *AgentImpl) IsKeyReady(ctx context.Context, req *pb.AgentKeyReadyReq) (*pb.AgentKeyReadyRes, error) {
	a.readyMu.RLock()
	readyStatus := a.groupKeyReady[req.Vni]
	a.readyMu.RUnlock()

	logrus.Infof("[%s] key-ready status for vni %d is: %t", a.name, req.Vni, readyStatus)
	return &pb.AgentKeyReadyRes{IsReady: readyStatus}, nil
}
