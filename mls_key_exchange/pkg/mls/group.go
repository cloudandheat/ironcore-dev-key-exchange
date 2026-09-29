// MLS group handling: events from the server, membership operations, commits and joins.
package mls

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"
	"strconv"

	pb "github.com/cloudandheat/ironcore-dev-key-exchange/proto"
	"github.com/sirupsen/logrus"
)

// groupID returns the ID of the MLS group of a VNI, as used by the Rust backend.
func groupID(vni uint32) string {
	return strconv.FormatUint(uint64(vni), 10)
}

// groupInfo returns the local state of the MLS group of a VNI from the Rust backend: whether it
// exists, its current epoch and its members.
func (a *AgentImpl) groupInfo(vni uint32) (*pb.GroupInfoRes, error) {
	return a.grpcClient.GetGroupInfo(context.Background(), &pb.GroupInfoReq{ClientId: a.name, GroupId: groupID(vni)})
}

// dropGroupLocked throws away the local MLS state of a group, together with its buffered commits
// and its rekey round. The SAs in dpservice stay untouched. Must be called with a.mu held.
func (a *AgentImpl) dropGroupLocked(vni uint32) {
	_, err := a.grpcClient.DropGroup(context.Background(), &pb.DropGroupReq{ClientId: a.name, GroupId: groupID(vni)})
	if err != nil {
		logrus.Errorf("[%s] Failed to drop local group state of VNI %d: %v", a.name, vni, err)
	}
	delete(a.rounds, vni)
	delete(a.commitBuffer, vni)
}

// reachedEpochLocked is called, whenever the group of a VNI moved to a new epoch, by creating,
// joining or committing. It exports the group secret of the epoch for its rekey round and tells the
// server. Must be called with a.mu held.
func (a *AgentImpl) reachedEpochLocked(vni uint32, epoch uint64) {
	res, err := a.grpcClient.ExportSharedSecret(context.Background(), &pb.ExportSecretReq{
		ClientId: a.name, GroupId: groupID(vni), Label: secretLabel,
	})
	if err != nil {
		logrus.Errorf("[%s] Failed to export secret of VNI %d epoch %d: %v", a.name, vni, epoch, err)
		return
	}

	logrus.Infof("[%s] VNI %d reached epoch %d", a.name, vni, epoch)
	a.rounds[vni] = &roundState{epoch: epoch, secret: res.SecretBytes}
	a.postReady(vni, epoch)
}

// resyncLocked throws away the local MLS state of a group, which became unusable, e.g. because it
// diverged from the rest of the group, and subscribes again, so that the server lets this agent be
// re-added. Must be called with a.mu held.
func (a *AgentImpl) resyncLocked(vni uint32) {
	logrus.Warnf("[%s] Local group state of VNI %d is unusable, requesting to be re-added", a.name, vni)
	a.dropGroupLocked(vni)
	if err := a.subscribeLocked(vni); err != nil {
		logrus.Errorf("[%s] Failed to subscribe VNI %d again: %v", a.name, vni, err)
	}
}

// handleEvent dispatches a message received from the server to its handler. Messages for VNIs this
// agent is not subscribed to are ignored. Called by the poll loop with a.mu held.
func (a *AgentImpl) handleEvent(env Envelope) {
	if !a.subscribed[env.VNI] {
		logrus.Debugf("[%s] Ignoring %s for unsubscribed VNI %d", a.name, env.Type, env.VNI)
		return
	}

	switch env.Type {
	case msgOp:
		var op Op
		if err := json.Unmarshal(env.Data, &op); err != nil {
			logrus.Errorf("[%s] Invalid op: %v", a.name, err)
			return
		}
		a.executeOp(env.VNI, op)

	case msgCommit:
		a.processCommit(env.VNI, env)

	case msgWelcome:
		a.joinGroup(env.VNI, env)

	case msgRoundPrepare, msgRoundInstall, msgRoundSwitch, msgRoundCleanup:
		var msg RoundMsg
		if err := json.Unmarshal(env.Data, &msg); err != nil {
			logrus.Errorf("[%s] Invalid round message: %v", a.name, err)
			return
		}
		a.handleRound(env.VNI, env.Type, msg)

	case msgPeerLeft:
		var msg PeerLeftMsg
		if err := json.Unmarshal(env.Data, &msg); err != nil {
			logrus.Errorf("[%s] Invalid peer_left message: %v", a.name, err)
			return
		}
		peer, err := underlayPrefix(msg.IP)
		if err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
			return
		}
		logrus.Infof("[%s] Peer %s (%s) left VNI %d", a.name, msg.User, peer, env.VNI)
		if err := a.deletePair(env.VNI, peer); err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
		}
	}
}

// executeOp is called on the committer of a group, when the server mandates a membership operation:
// adding or re-adding an agent (a single commit swaps out the old leaf of a restarted agent),
// removing an agent or rotating the key. It sends the resulting commit to the other members and the
// welcome to an added agent, reports the result to the server and afterwards starts into the new
// epoch itself.
func (a *AgentImpl) executeOp(vni uint32, op Op) {
	logrus.Infof("[%s] Mandated to execute %s(%s) on VNI %d", a.name, op.Kind, op.User, vni)

	result := OpResult{ID: op.ID, Failed: true}
	defer func() {
		if info, err := a.groupInfo(vni); err == nil && info.Exists {
			result.Epoch = info.Epoch
			result.Members = info.Members
		}
		body, _ := json.Marshal(result)
		if err := a.serverPost("/op_done", url.Values{"user": {a.name}, "vni": {groupID(vni)}}, body); err != nil {
			logrus.Errorf("[%s] Failed to report op %d: %v", a.name, op.ID, err)
		}
		if !result.Failed {
			a.reachedEpochLocked(vni, result.Epoch)
		}
	}()

	before, err := a.groupInfo(vni)
	if err != nil || !before.Exists {
		logrus.Errorf("[%s] Unable to execute op, no group state for VNI %d: %v", a.name, vni, err)
		return
	}

	var commit []byte
	var skip []string
	switch op.Kind {
	case opAdd, opReadd:
		kp, err := a.fetchKP(op.User)
		if err != nil {
			logrus.Errorf("[%s] %v", a.name, err)
			return
		}
		// replaces the old leaf of the user, if there still is one, otherwise it is a plain add
		res, err := a.grpcClient.SwapMember(context.Background(), &pb.SwapMemberReq{
			ClientId: a.name, GroupId: groupID(vni), TargetClientId: op.User, TargetKpHex: string(kp),
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to add %s: %v", a.name, op.User, err)
			return
		}
		tree, err := a.grpcClient.SerializeTree(context.Background(), &pb.SerializeTreeReq{GroupId: groupID(vni)})
		if err != nil {
			logrus.Errorf("[%s] Failed to serialize tree of VNI %d: %v", a.name, vni, err)
			return
		}
		welcome, _ := json.Marshal(WelcomePayload{Welcome: res.WelcomeBytes, Tree: tree.TreeBytes})
		a.sendMsg(op.User, msgWelcome, before.Epoch+1, vni, welcome)
		commit = res.CommitBytes
		skip = []string{op.User}

	case opRemove:
		res, err := a.grpcClient.RemoveMember(context.Background(), &pb.RemoveReq{
			ClientId: a.name, GroupId: groupID(vni), TargetClientId: op.User,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to remove %s: %v", a.name, op.User, err)
			return
		}
		commit = res.CommitBytes
		skip = []string{op.User}

	case opUpdate:
		res, err := a.grpcClient.SelfUpdate(context.Background(), &pb.SelfUpdateReq{ClientId: a.name, GroupId: groupID(vni)})
		if err != nil {
			logrus.Errorf("[%s] Failed to self-update: %v", a.name, err)
			return
		}
		commit = res.CommitBytes

	default:
		logrus.Errorf("[%s] Unknown op %s", a.name, op.Kind)
		return
	}

	for _, member := range before.Members {
		if member != a.name && !slices.Contains(skip, member) {
			a.sendMsg(member, msgCommit, before.Epoch, vni, commit)
		}
	}
	result.Failed = false
}

// bufferCommit keeps a commit, which can not be processed yet, because the agent has not joined the
// group yet or the commit arrived before the one of an earlier epoch.
func (a *AgentImpl) bufferCommit(vni uint32, env Envelope) {
	if a.commitBuffer[vni] == nil {
		a.commitBuffer[vni] = make(map[uint64]Envelope)
	}
	a.commitBuffer[vni][env.Epoch] = env
}

// processBufferedCommits processes the buffered commit for the given epoch, if there is one, and
// drops buffered commits of older epochs, which are outdated.
func (a *AgentImpl) processBufferedCommits(vni uint32, epoch uint64) {
	for e := range a.commitBuffer[vni] {
		if e < epoch {
			delete(a.commitBuffer[vni], e)
		}
	}
	if env, ok := a.commitBuffer[vni][epoch]; ok {
		delete(a.commitBuffer[vni], epoch)
		a.processCommit(vni, env)
	}
}

// processCommit applies a commit, which the committer sent, to the local group and moves it to the
// next epoch. Commits for later epochs are buffered and those for earlier epochs ignored. If the
// commit can not be applied, the local state has diverged and the agent requests to be re-added. If
// the commit removed this agent, the local group is dropped.
func (a *AgentImpl) processCommit(vni uint32, env Envelope) {
	info, err := a.groupInfo(vni)
	if err != nil {
		logrus.Errorf("[%s] Unable to get group state of VNI %d: %v", a.name, vni, err)
		return
	}
	if !info.Exists || env.Epoch > info.Epoch {
		// not joined yet, or commits arrived out of order
		a.bufferCommit(vni, env)
		return
	}
	if env.Epoch < info.Epoch {
		return
	}

	_, err = a.grpcClient.ProcessCommit(context.Background(), &pb.ProcessCommitReq{
		ClientId: a.name, GroupId: groupID(vni), CommitBytes: env.Data,
	})
	if err != nil {
		logrus.Errorf("[%s] Failed to process commit of epoch %d: %v", a.name, env.Epoch, err)
		a.resyncLocked(vni)
		return
	}

	info, err = a.groupInfo(vni)
	if err != nil {
		logrus.Errorf("[%s] Unable to get group state of VNI %d: %v", a.name, vni, err)
		return
	}
	if !info.Exists || !slices.Contains(info.Members, a.name) {
		logrus.Infof("[%s] Removed from group of VNI %d", a.name, vni)
		a.dropGroupLocked(vni)
		return
	}

	a.reachedEpochLocked(vni, info.Epoch)
	a.processBufferedCommits(vni, info.Epoch)
}

// joinGroup joins the group of a VNI from a welcome sent by the committer, afterwards processes
// commits which arrived before the welcome and uploads a key package to replace the one used up by
// the join.
func (a *AgentImpl) joinGroup(vni uint32, env Envelope) {
	var payload WelcomePayload
	if err := json.Unmarshal(env.Data, &payload); err != nil {
		logrus.Errorf("[%s] Invalid welcome: %v", a.name, err)
		return
	}

	_, err := a.grpcClient.JoinGroup(context.Background(), &pb.JoinGroupReq{
		ClientId: a.name, GroupId: groupID(vni), WelcomeBytes: payload.Welcome, TreeBytes: payload.Tree,
	})
	if err != nil {
		logrus.Errorf("[%s] Failed to process join of VNI %d: %v", a.name, vni, err)
		a.resyncLocked(vni)
		return
	}
	go a.generateAndUploadKP()

	info, err := a.groupInfo(vni)
	if err != nil {
		logrus.Errorf("[%s] Unable to get group state of VNI %d: %v", a.name, vni, err)
		return
	}
	logrus.Infof("[%s] Joined VNI %d at epoch %d", a.name, vni, info.Epoch)

	a.reachedEpochLocked(vni, info.Epoch)
	a.processBufferedCommits(vni, info.Epoch)
}
