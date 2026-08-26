package mls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	pb "github.com/cloudandheat/ironcore-dev-key-exchange/proto"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Envelope struct {
	Type    string `json:"Type"`
	From    string `json:"From"`
	Epoch   uint64 `json:"Epoch"`
	GroupID string `json:"GroupID"`
	Data    []byte `json:"Data"`
	IPs     string `json:"IPs"`
}

type InvitePayload struct {
	Welcome string `json:"welcome"`
	Tree    string `json:"tree"`
	Epoch   uint64 `json:"epoch"`
}

var (
	groupMembers = make(map[string][]string)
	groupEpochs  = make(map[string]uint64)
	commitBuffer = make(map[string]map[uint64]Envelope)
)

type AgentImpl struct {
	pb.UnimplementedAgentServiceServer
	name       string
	serverURL  string
	clientIP   string
	grpcClient pb.MlsServiceClient
	vniToGroup map[uint32]string
}

func NewAgent() *AgentImpl {
	return &AgentImpl{
		vniToGroup: make(map[uint32]string),
	}
}

// NEW: Server startup logic moved here from main.go
func (a *AgentImpl) Start(port string) {
	lis, err := net.Listen("tcp", port)
	if err != nil {
		logrus.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcServer, a)

	logrus.Infof("[AGENT] Starting Go Client Agent Daemon on %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		logrus.Fatalf("Failed to serve: %v", err)
	}
}

func (c *AgentImpl) startListener() {
	go func() {
		for {
			url := fmt.Sprintf("%s/poll?user=%s", c.serverURL, c.name)
			resp, err := http.Get(url)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}
			if resp.StatusCode == http.StatusNoContent {
				resp.Body.Close()
				continue
			}
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				time.Sleep(2 * time.Second)
				continue
			}

			// Decode the entire Envelope from the JSON body
			var env Envelope
			err = json.NewDecoder(resp.Body).Decode(&env)
			resp.Body.Close()

			if err != nil {
				logrus.Errorf("[%s] Failed to decode poll response: %v", c.name, err)
				time.Sleep(2 * time.Second)
				continue
			}

			c.handleEvent(env)
		}
	}()
}

func sendMsg(serverURL, to, msgType, from string, epoch uint64, groupID string, data []byte) {
	url := fmt.Sprintf("%s/send?to=%s&type=%s&from=%s&epoch=%d&group=%s", serverURL, to, msgType, from, epoch, groupID)
	http.Post(url, "application/octet-stream", bytes.NewBuffer(data))
}

func (c *AgentImpl) handleSecretUpdate(action string, epoch uint64, secret []byte, ownIP string, vniIPs string) {
	logrus.Infof("----------------- [%s] %s", c.name, action)

	ownNetIP := net.ParseIP(ownIP)

	ips := strings.Split(vniIPs, ",")
	for _, peerIP := range ips {
		peerIP = strings.TrimSpace(peerIP)

		if peerIP == "" || peerIP == ownIP {
			continue
		}

		peerNetIP := net.ParseIP(peerIP)
		var lower, higher string

		// Order ip-addresses based on their numerical value
		if ownNetIP != nil && peerNetIP != nil {
			if bytes.Compare(ownNetIP.To16(), peerNetIP.To16()) < 0 {
				lower = ownIP
				higher = peerIP
			} else {
				lower = peerIP
				higher = ownIP
			}
		} else {
			if ownIP < peerIP {
				lower = ownIP
				higher = peerIP
			} else {
				lower = peerIP
				higher = ownIP
			}
		}

		// Create a deterministic context string for this specific pair and epoch
		contextString := fmt.Sprintf("%s:%s:%d", lower, higher, epoch)

		// Generate 4 bype SPI
		h := fnv.New32a()
		h.Write([]byte(contextString))
		SPI := h.Sum32()

		// Generate a secure 4-byte salt using HMAC-SHA256
		// Using the OpenMLS shared secret as the HMAC key guarantees the output
		// is cryptographically tied to the group's current secure state.
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(contextString))
		secureHash := mac.Sum(nil)

		// Extract the first 4 bytes to use as the salt
		salt := secureHash[:4]

		logrus.Infof("------------------------------ Debug-output: %d : %x : %s : %s : %d : %x", SPI, salt, lower, higher, epoch, secret)
	}
}

func (c *AgentImpl) Init(ctx context.Context, req *pb.AgentInitReq) (*pb.AgentEmpty, error) {
	logrus.Infof("------------------------------ Init Agent")
	c.name = req.ClientName
	c.serverURL = req.BrokerUrl
	c.clientIP = req.ClientIp

	grpcURL := os.Getenv("RUST_GRPC_URL")
	conn, err := grpc.NewClient(grpcURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to grpc: %v", err)
	}
	c.grpcClient = pb.NewMlsServiceClient(conn)

	_, err = c.grpcClient.GenerateCredential(context.Background(), &pb.GenerateReq{ClientId: c.name})
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential: %v", err)
	}

	kpRes, err := c.grpcClient.GenerateKeyPackage(context.Background(), &pb.GenerateReq{ClientId: c.name})
	if err != nil {
		return nil, fmt.Errorf("failed to generate key package: %v", err)
	}

	pubKey := []byte(kpRes.KeyPackageHex)
	url := fmt.Sprintf("%s/upload_kp?user=%s", c.serverURL, c.name)

	httpClient := &http.Client{Timeout: 3 * time.Second}
	for {
		resp, err := httpClient.Post(url, "application/octet-stream", bytes.NewBuffer(pubKey))
		if err != nil {
			logrus.Infof("[%s] Broker not reachable yet: %v\n", c.name, err)
		} else {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
			logrus.Infof("[%s] Broker returned status %d, waiting...\n", c.name, resp.StatusCode)
		}
		time.Sleep(1 * time.Second)
	}

	c.startListener()
	return &pb.AgentEmpty{}, nil
}

func (c *AgentImpl) Subscribe(ctx context.Context, req *pb.AgentSubscribeReq) (*pb.AgentEmpty, error) {
	logrus.Infof("------------------------------ Subscribe VNI: %d", req.Vni)
	url := fmt.Sprintf("%s/subscribe?user=%s&id=%d&ip=%s", c.serverURL, c.name, req.Vni, c.clientIP)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("broker subscribe error: %v", err)
	}
	defer resp.Body.Close()

	var bResp map[string]string
	json.NewDecoder(resp.Body).Decode(&bResp)

	if bResp["status"] == "created" {
		groupID := bResp["group_id"]
		c.vniToGroup[req.Vni] = groupID
		logrus.Infof("------------------------------ [%s] Subscribed. Creating group %s for VNI %d", c.name, groupID, req.Vni)

		_, err := c.grpcClient.CreateGroup(context.Background(), &pb.CreateGroupReq{
			ClientId: c.name, GroupId: groupID,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to create group %s: %v", c.name, groupID, err)
			return nil, err
		}

		groupMembers[groupID] = append(groupMembers[groupID], c.name)
		groupEpochs[groupID] = 1
	} else {
		groupID := bResp["group_id"]
		c.vniToGroup[req.Vni] = groupID // Save the mapping here too
		logrus.Infof("------------------------------ [%s] Subscribed to VNI %d, waiting for invite to group %s", c.name, req.Vni, bResp["group_id"])
	}
	return &pb.AgentEmpty{}, nil
}

func (c *AgentImpl) Unsubscribe(ctx context.Context, req *pb.AgentUnsubscribeReq) (*pb.AgentEmpty, error) {
	logrus.Infof("------------------------------ Unsubscribe VNI: %d", req.Vni)

	// Tell the broker we are leaving (this triggers the initiator to remove us globally)
	url := fmt.Sprintf("%s/unsubscribe?user=%s&id=%d", c.serverURL, c.name, req.Vni)
	http.Get(url)

	// Drop the group from our local Rust memory so we stop processing future commits
	if groupID, exists := c.vniToGroup[req.Vni]; exists {
		_, err := c.grpcClient.DropGroup(context.Background(), &pb.DropGroupReq{
			ClientId: c.name,
			GroupId:  groupID,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to drop local group state: %v", c.name, err)
		} else {
			logrus.Infof("[%s] Successfully dropped Group %s from local Rust state.", c.name, groupID)
		}

		// Clean up our local map
		delete(c.vniToGroup, req.Vni)
	}

	return &pb.AgentEmpty{}, nil
}

func (c *AgentImpl) InviteMember(groupID string, peerName string, ips string) {
	resp, err := http.Get(fmt.Sprintf("%s/get_kp?user=%s", c.serverURL, peerName))
	if err != nil {
		logrus.Errorf("[%s] Failed to get key package for %s: %v", c.name, peerName, err)
		return
	}
	peerPubKey, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	currentEpoch := groupEpochs[groupID]

	res, err := c.grpcClient.InviteMembers(context.Background(), &pb.InviteReq{
		ClientId: c.name, GroupId: groupID, TargetKpHex: string(peerPubKey),
	})
	if err != nil {
		logrus.Errorf("------------------------------ [%s] Failed to invite %s: %v", c.name, peerName, err)
		return
	}

	treeRes, err := c.grpcClient.SerializeTree(context.Background(), &pb.SerializeTreeReq{GroupId: groupID})
	if err != nil {
		logrus.Errorf("------------------------------ [%s] Failed to serialize tree for group %s: %v", c.name, groupID, err)
		return
	}

	inv := InvitePayload{
		Welcome: base64.StdEncoding.EncodeToString(res.WelcomeBytes),
		Tree:    base64.StdEncoding.EncodeToString(treeRes.TreeBytes),
		Epoch:   currentEpoch + 1,
	}
	invData, _ := json.Marshal(inv)

	sendMsg(c.serverURL, peerName, "invite_payload", c.name, currentEpoch+1, groupID, invData)

	for _, member := range groupMembers[groupID] {
		if member != c.name && member != peerName {
			sendMsg(c.serverURL, member, "commit", c.name, currentEpoch, groupID, res.CommitBytes)
		}
	}

	groupMembers[groupID] = append(groupMembers[groupID], peerName)
	groupEpochs[groupID] = currentEpoch + 1

	secret, err := c.GetSharedSecret(groupID)
	if err == nil {
		c.handleSecretUpdate("Tree Updated", currentEpoch+1, secret, c.clientIP, ips)
	} else {
		logrus.Errorf("------------------------------ [%s] Failed to extract shared secret after invite: %v", c.name, err)
	}
}

func (c *AgentImpl) processCommit(groupID string, env Envelope) {
	expectedEpoch := groupEpochs[groupID]

	if env.Epoch > expectedEpoch {
		if commitBuffer[groupID] == nil {
			commitBuffer[groupID] = make(map[uint64]Envelope)
		}
		commitBuffer[groupID][env.Epoch] = env
		return
	}

	if env.Epoch == expectedEpoch {
		_, err := c.grpcClient.ProcessCommit(context.Background(), &pb.ProcessCommitReq{
			ClientId: c.name, GroupId: groupID, CommitBytes: env.Data,
		})

		if err != nil {
			logrus.Errorf("----------------- [%s] Failed to process commit in epoch %d: %v", c.name, env.Epoch, err)
			return
		}

		groupEpochs[groupID] = expectedEpoch + 1
		secret, err := c.GetSharedSecret(groupID)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after commit processing: %v", c.name, err)
			return
		}

		c.handleSecretUpdate("Tree Updated", expectedEpoch+1, secret, c.clientIP, env.IPs)

		if bufEnv, ok := commitBuffer[groupID][groupEpochs[groupID]]; ok {
			delete(commitBuffer[groupID], groupEpochs[groupID])
			c.processCommit(groupID, bufEnv)
		}
	}
}

func (c *AgentImpl) GetSharedSecret(groupID string) ([]byte, error) {
	res, err := c.grpcClient.ExportSharedSecret(context.Background(), &pb.ExportSecretReq{
		ClientId: c.name, GroupId: groupID, Label: "default-app-secret",
	})
	if err != nil {
		return nil, err
	}
	return res.SecretBytes, nil
}

func (c *AgentImpl) handleEvent(env Envelope) {
	switch env.Type {
	case "add_request":
		var req map[string]string
		json.Unmarshal(env.Data, &req)
		logrus.Infof("----------------- [%s] Orchestrator mandated invite of %s to Group %s\n", c.name, req["user"], req["group_id"])
		c.InviteMember(req["group_id"], req["user"], env.IPs)

	case "remove_request":
		var req map[string]string
		json.Unmarshal(env.Data, &req)
		target := req["user"]
		logrus.Infof("----------------- [%s] Orchestrator mandated removal of %s from Group %s\n", c.name, target, env.GroupID)

		currentEpoch := groupEpochs[env.GroupID]
		res, err := c.grpcClient.RemoveMember(context.Background(), &pb.RemoveReq{
			ClientId: c.name, GroupId: env.GroupID, TargetClientId: target,
		})
		if err != nil {
			logrus.Errorf("------------------------------ [%s] Failed to remove %s: %v", c.name, target, err)
			return
		}

		for _, member := range groupMembers[env.GroupID] {
			if member != c.name && member != target {
				sendMsg(c.serverURL, member, "commit", c.name, currentEpoch, env.GroupID, res.CommitBytes)
			}
		}

		var newMembers []string
		for _, m := range groupMembers[env.GroupID] {
			if m != target {
				newMembers = append(newMembers, m)
			}
		}
		groupMembers[env.GroupID] = newMembers
		groupEpochs[env.GroupID] = currentEpoch + 1

		secret, err := c.GetSharedSecret(env.GroupID)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after member removal: %v", c.name, err)
			return
		}

		actionMsg := fmt.Sprintf("Tree Updated. REMOVED %s", target)
		c.handleSecretUpdate(actionMsg, currentEpoch+1, secret, c.clientIP, env.IPs)

	case "invite_payload":
		var inv InvitePayload
		json.Unmarshal(env.Data, &inv)

		wBytes, err := base64.StdEncoding.DecodeString(inv.Welcome)
		if err != nil {
			logrus.Errorf("[%s] Failed to base64 decode Welcome bytes: %v", c.name, err)
			return
		}

		tBytes, err := base64.StdEncoding.DecodeString(inv.Tree)
		if err != nil {
			logrus.Errorf("[%s] Failed to base64 decode Tree bytes: %v", c.name, err)
			return
		}

		_, err = c.grpcClient.JoinGroup(context.Background(), &pb.JoinGroupReq{
			ClientId: c.name, GroupId: env.GroupID, WelcomeBytes: wBytes, TreeBytes: tBytes,
		})
		if err != nil {
			logrus.Errorf("----------------- [%s] Failed to process join: %v", c.name, err)
			return
		}

		groupEpochs[env.GroupID] = inv.Epoch
		secret, err := c.GetSharedSecret(env.GroupID)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after join: %v", c.name, err)
			return
		}

		actionMsg := fmt.Sprintf("Joined Group %s!", env.GroupID)
		c.handleSecretUpdate(actionMsg, inv.Epoch, secret, c.clientIP, env.IPs)

	case "commit":
		c.processCommit(env.GroupID, env)

	case "update_request":
		var req map[string]string
		json.Unmarshal(env.Data, &req)
		logrus.Infof("----------------- [%s] Orchestrator mandated Key Rotation (Self-Update) for Group %s\n", c.name, env.GroupID)

		currentEpoch := groupEpochs[env.GroupID]
		res, err := c.grpcClient.SelfUpdate(context.Background(), &pb.SelfUpdateReq{
			ClientId: c.name, GroupId: env.GroupID,
		})
		if err != nil {
			logrus.Errorf("------------------------------ [%s] Failed to self-update: %v", c.name, err)
			return
		}

		// Broadcast the key rotation commit to all other members
		for _, member := range groupMembers[env.GroupID] {
			if member != c.name {
				sendMsg(c.serverURL, member, "commit", c.name, currentEpoch, env.GroupID, res.CommitBytes)
			}
		}

		// Apply local epoch bump
		groupEpochs[env.GroupID] = currentEpoch + 1

		secret, err := c.GetSharedSecret(env.GroupID)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after key rotation: %v", c.name, err)
			return
		}

		logrus.Infof("----------------- [%s] Tree Updated (Epoch %d). KEY ROTATION SUCCESSFUL. GroupKey Preview: %x\n", c.name, currentEpoch+1, secret[:4])
	}
}
