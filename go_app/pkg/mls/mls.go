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
	"sync"
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

type AgentImpl struct {
	pb.UnimplementedAgentServiceServer
	mu         sync.RWMutex
	name       string
	serverURL  string
	clientIP   string
	grpcClient pb.MlsServiceClient

	vniToGroup    map[uint32]string
	groupKeyReady map[string]bool

	groupMembers map[string][]string
	groupEpochs  map[string]uint64
	commitBuffer map[string]map[uint64]Envelope
}

func NewAgent() *AgentImpl {
	return &AgentImpl{
		vniToGroup:    make(map[uint32]string),
		groupKeyReady: make(map[string]bool),
		groupMembers:  make(map[string][]string),
		groupEpochs:   make(map[string]uint64),
		commitBuffer:  make(map[string]map[uint64]Envelope),
	}
}

func (a *AgentImpl) Start(port string) {
	a.mu.RLock()
	name := a.name
	a.mu.RUnlock()

	logrus.Infof("[%s] Start", name)

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
			c.mu.RLock()
			serverURL := c.serverURL
			name := c.name
			c.mu.RUnlock()

			url := fmt.Sprintf("%s/poll?user=%s", serverURL, name)
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

			var env Envelope
			err = json.NewDecoder(resp.Body).Decode(&env)
			resp.Body.Close()

			if err != nil {
				logrus.Errorf("[%s] Failed to decode poll response: %v", name, err)
				time.Sleep(2 * time.Second)
				continue
			}

			c.handleEvent(env)
		}
	}()
}

// generateAndUploadKP generates a fresh KeyPackage in Rust and pushes it to the broker queue
func (c *AgentImpl) generateAndUploadKP() {
	c.mu.RLock()
	name := c.name
	grpcClient := c.grpcClient
	serverURL := c.serverURL
	c.mu.RUnlock()

	kpRes, err := grpcClient.GenerateKeyPackage(context.Background(), &pb.GenerateReq{ClientId: name})
	if err != nil {
		logrus.Errorf("[%s] Failed to generate key package: %v", name, err)
		return
	}

	pubKey := []byte(kpRes.KeyPackageHex)
	url := fmt.Sprintf("%s/upload_kp?user=%s", serverURL, name)

	httpClient := &http.Client{Timeout: 3 * time.Second}
	resp, err := httpClient.Post(url, "application/octet-stream", bytes.NewBuffer(pubKey))
	if err == nil {
		resp.Body.Close()
	} else {
		logrus.Warnf("[%s] Failed to upload KeyPackage: %v", name, err)
	}
}

func sendMsg(serverURL, to, msgType, from string, epoch uint64, groupID string, data []byte) {
	url := fmt.Sprintf("%s/send?to=%s&type=%s&from=%s&epoch=%d&group=%s", serverURL, to, msgType, from, epoch, groupID)
	http.Post(url, "application/octet-stream", bytes.NewBuffer(data))
}

func (c *AgentImpl) handleSecretUpdate(groupID string, action string, epoch uint64, secret []byte, ownIP string, vniIPs string) {
	c.mu.RLock()
	name := c.name
	c.mu.RUnlock()

	logrus.Infof("[%s] %s", name, action)
	ownNetIP := net.ParseIP(ownIP)
	ips := strings.Split(vniIPs, ",")

	for _, peerIP := range ips {
		peerIP = strings.TrimSpace(peerIP)
		if peerIP == "" || peerIP == ownIP {
			continue
		}

		peerNetIP := net.ParseIP(peerIP)
		var lower, higher string

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

		contextString := fmt.Sprintf("%s:%s:%d", lower, higher, epoch)

		h := fnv.New32a()
		h.Write([]byte(contextString))
		SPI := h.Sum32()

		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(contextString))
		secureHash := mac.Sum(nil)
		salt := secureHash[:4]

		logrus.Infof("-------------Debug-output: %d : %x : %s : %s : %d : %x", SPI, salt, lower, higher, epoch, secret)
		c.mu.Lock()
		c.groupKeyReady[groupID] = true
		c.mu.Unlock()
	}
}

func (c *AgentImpl) Init(ctx context.Context, req *pb.AgentInitReq) (*pb.AgentEmpty, error) {
	logrus.Infof("-------------Init Agent")

	grpcURL := os.Getenv("RUST_GRPC_URL")
	logrus.Infof("-------------grpcURL %s", grpcURL)

	conn, err := grpc.NewClient(grpcURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to grpc: %v", err)
	}
	grpcClient := pb.NewMlsServiceClient(conn)

	c.mu.Lock()
	c.name = req.ClientName
	c.serverURL = req.BrokerUrl
	c.clientIP = req.ClientIp
	c.grpcClient = grpcClient
	c.mu.Unlock()

	_, err = grpcClient.GenerateCredential(context.Background(), &pb.GenerateReq{ClientId: req.ClientName})
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential: %v", err)
	}

	// CHANGED: Pre-load the broker with a batch of 5 KeyPackages to buffer concurrent invites
	for i := 0; i < 5; i++ {
		c.generateAndUploadKP()
	}

	c.startListener()
	return &pb.AgentEmpty{}, nil
}

func (c *AgentImpl) Subscribe(ctx context.Context, req *pb.AgentSubscribeReq) (*pb.AgentEmpty, error) {
	c.mu.RLock()
	name := c.name
	serverURL := c.serverURL
	clientIP := c.clientIP
	grpcClient := c.grpcClient
	c.mu.RUnlock()

	logrus.Infof("[%s] Subscribe VNI: %d", name, req.Vni)
	url := fmt.Sprintf("%s/subscribe?user=%s&id=%d&ip=%s", serverURL, name, req.Vni, clientIP)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("broker subscribe error: %v", err)
	}
	defer resp.Body.Close()

	var bResp map[string]string
	json.NewDecoder(resp.Body).Decode(&bResp)

	if bResp["status"] == "created" {
		groupID := bResp["group_id"]

		c.mu.Lock()
		c.vniToGroup[req.Vni] = groupID
		c.mu.Unlock()

		logrus.Infof("[%s] Subscribed. Creating group %s for VNI %d", name, groupID, req.Vni)

		_, err := grpcClient.CreateGroup(context.Background(), &pb.CreateGroupReq{
			ClientId: name, GroupId: groupID,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to create group %s: %v", name, groupID, err)
			return nil, err
		}

		c.mu.Lock()
		c.groupMembers[groupID] = append(c.groupMembers[groupID], name)
		c.groupEpochs[groupID] = 1
		c.mu.Unlock()
	} else {
		groupID := bResp["group_id"]
		c.mu.Lock()
		c.vniToGroup[req.Vni] = groupID
		c.mu.Unlock()

		logrus.Infof("[%s] Subscribed to VNI %d, waiting for invite to group %s", name, req.Vni, bResp["group_id"])
	}
	return &pb.AgentEmpty{}, nil
}

func (c *AgentImpl) Unsubscribe(ctx context.Context, req *pb.AgentUnsubscribeReq) (*pb.AgentEmpty, error) {
	c.mu.RLock()
	name := c.name
	serverURL := c.serverURL
	grpcClient := c.grpcClient
	c.mu.RUnlock()

	logrus.Infof("[%s] Unsubscribe VNI: %d", name, req.Vni)

	url := fmt.Sprintf("%s/unsubscribe?user=%s&id=%d", serverURL, name, req.Vni)
	http.Get(url)

	c.mu.Lock()
	groupID, exists := c.vniToGroup[req.Vni]
	if exists {
		delete(c.vniToGroup, req.Vni)
		delete(c.groupKeyReady, groupID)
		delete(c.groupMembers, groupID)
		delete(c.groupEpochs, groupID)
		delete(c.commitBuffer, groupID)
	}
	c.mu.Unlock()

	if exists {
		_, err := grpcClient.DropGroup(context.Background(), &pb.DropGroupReq{
			ClientId: name,
			GroupId:  groupID,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to drop local group state: %v", name, err)
		} else {
			logrus.Infof("[%s] Successfully dropped Group %s from local Rust state.", name, groupID)
		}
	}

	return &pb.AgentEmpty{}, nil
}

func (c *AgentImpl) InviteMember(groupID string, peerName string, ips string) {
	c.mu.RLock()
	name := c.name
	serverURL := c.serverURL
	grpcClient := c.grpcClient
	clientIP := c.clientIP
	currentEpoch := c.groupEpochs[groupID]
	members := append([]string(nil), c.groupMembers[groupID]...)
	c.mu.RUnlock()

	logrus.Infof("[%s] InviteMember group: %s and peer: %s", name, groupID, peerName)

	// CHANGED: Retry loop in case the peer's queue of KeyPackages is temporarily depleted
	var peerPubKey []byte
	for i := 0; i < 15; i++ {
		resp, err := http.Get(fmt.Sprintf("%s/get_kp?user=%s", serverURL, peerName))
		if err == nil && resp.StatusCode == http.StatusOK {
			peerPubKey, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		logrus.Warnf("[%s] KeyPackage for %s not available yet, waiting...", name, peerName)
		time.Sleep(1 * time.Second)
	}

	if peerPubKey == nil {
		logrus.Errorf("[%s] Failed to retrieve KeyPackage for %s after retries", name, peerName)
		return
	}

	res, err := grpcClient.InviteMembers(context.Background(), &pb.InviteReq{
		ClientId: name, GroupId: groupID, TargetKpHex: string(peerPubKey),
	})
	if err != nil {
		logrus.Errorf("[%s] Failed to invite %s: %v", name, peerName, err)
		return
	}

	treeRes, err := grpcClient.SerializeTree(context.Background(), &pb.SerializeTreeReq{GroupId: groupID})
	if err != nil {
		logrus.Errorf("[%s] Failed to serialize tree for group %s: %v", name, groupID, err)
		return
	}

	inv := InvitePayload{
		Welcome: base64.StdEncoding.EncodeToString(res.WelcomeBytes),
		Tree:    base64.StdEncoding.EncodeToString(treeRes.TreeBytes),
		Epoch:   currentEpoch + 1,
	}
	invData, _ := json.Marshal(inv)

	sendMsg(serverURL, peerName, "invite_payload", name, currentEpoch+1, groupID, invData)

	for _, member := range members {
		if member != name && member != peerName {
			sendMsg(serverURL, member, "commit", name, currentEpoch, groupID, res.CommitBytes)
		}
	}

	c.mu.Lock()
	c.groupMembers[groupID] = append(c.groupMembers[groupID], peerName)
	c.groupEpochs[groupID] = currentEpoch + 1
	c.mu.Unlock()

	secret, err := c.GetSharedSecret(groupID)
	if err == nil {
		c.handleSecretUpdate(groupID, "Tree Updated", currentEpoch+1, secret, clientIP, ips)
	} else {
		logrus.Errorf("[%s] Failed to extract shared secret after invite: %v", name, err)
	}
}

func (c *AgentImpl) IsKeyReady(ctx context.Context, req *pb.AgentKeyReadyReq) (*pb.AgentKeyReadyRes, error) {
	c.mu.RLock()
	groupID, exists := c.vniToGroup[req.Vni]
	readyStatus := false
	if exists {
		readyStatus = c.groupKeyReady[groupID]
	}
	c.mu.RUnlock()

	if !exists {
		return &pb.AgentKeyReadyRes{IsReady: false}, nil
	}
	return &pb.AgentKeyReadyRes{IsReady: readyStatus}, nil
}

func (c *AgentImpl) processCommit(groupID string, env Envelope) {
	c.mu.RLock()
	expectedEpoch := c.groupEpochs[groupID]
	name := c.name
	grpcClient := c.grpcClient
	clientIP := c.clientIP
	c.mu.RUnlock()

	if env.Epoch > expectedEpoch {
		c.mu.Lock()
		if c.commitBuffer[groupID] == nil {
			c.commitBuffer[groupID] = make(map[uint64]Envelope)
		}
		c.commitBuffer[groupID][env.Epoch] = env
		c.mu.Unlock()
		return
	}

	if env.Epoch == expectedEpoch {
		_, err := grpcClient.ProcessCommit(context.Background(), &pb.ProcessCommitReq{
			ClientId: name, GroupId: groupID, CommitBytes: env.Data,
		})

		if err != nil {
			logrus.Errorf("[%s] Failed to process commit in epoch %d: %v", name, env.Epoch, err)
			return
		}

		c.mu.Lock()
		c.groupEpochs[groupID] = expectedEpoch + 1
		c.mu.Unlock()

		secret, err := c.GetSharedSecret(groupID)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after commit processing: %v", name, err)
			return
		}

		c.handleSecretUpdate(groupID, "Tree Updated", expectedEpoch+1, secret, clientIP, env.IPs)

		c.mu.Lock()
		bufEnv, ok := c.commitBuffer[groupID][expectedEpoch+1]
		if ok {
			delete(c.commitBuffer[groupID], expectedEpoch+1)
		}
		c.mu.Unlock()

		if ok {
			c.processCommit(groupID, bufEnv)
		}
	}
}

func (c *AgentImpl) GetSharedSecret(groupID string) ([]byte, error) {
	c.mu.RLock()
	name := c.name
	grpcClient := c.grpcClient
	c.mu.RUnlock()

	res, err := grpcClient.ExportSharedSecret(context.Background(), &pb.ExportSecretReq{
		ClientId: name, GroupId: groupID, Label: "default-app-secret",
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

		c.mu.RLock()
		name := c.name
		c.mu.RUnlock()

		logrus.Infof("[%s] Orchestrator mandated invite of %s to Group %s\n", name, req["user"], req["group_id"])
		c.InviteMember(req["group_id"], req["user"], env.IPs)

	case "remove_request":
		var req map[string]string
		json.Unmarshal(env.Data, &req)
		target := req["user"]

		c.mu.RLock()
		name := c.name
		serverURL := c.serverURL
		grpcClient := c.grpcClient
		clientIP := c.clientIP
		currentEpoch := c.groupEpochs[env.GroupID]
		members := append([]string(nil), c.groupMembers[env.GroupID]...)
		c.mu.RUnlock()

		logrus.Infof("[%s] Orchestrator mandated removal of %s from Group %s\n", name, target, env.GroupID)

		res, err := grpcClient.RemoveMember(context.Background(), &pb.RemoveReq{
			ClientId: name, GroupId: env.GroupID, TargetClientId: target,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to remove %s: %v", name, target, err)
			return
		}

		for _, member := range members {
			if member != name && member != target {
				sendMsg(serverURL, member, "commit", name, currentEpoch, env.GroupID, res.CommitBytes)
			}
		}

		c.mu.Lock()
		var newMembers []string
		for _, m := range c.groupMembers[env.GroupID] {
			if m != target {
				newMembers = append(newMembers, m)
			}
		}
		c.groupMembers[env.GroupID] = newMembers
		c.groupEpochs[env.GroupID] = currentEpoch + 1
		c.mu.Unlock()

		secret, err := c.GetSharedSecret(env.GroupID)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after member removal: %v", name, err)
			return
		}

		actionMsg := fmt.Sprintf("Tree Updated. REMOVED %s", target)
		c.handleSecretUpdate(env.GroupID, actionMsg, currentEpoch+1, secret, clientIP, env.IPs)

	case "invite_payload":
		var inv InvitePayload
		json.Unmarshal(env.Data, &inv)

		wBytes, err := base64.StdEncoding.DecodeString(inv.Welcome)
		if err != nil {
			logrus.Errorf("[AGENT] Failed to base64 decode Welcome bytes: %v", err)
			return
		}

		tBytes, err := base64.StdEncoding.DecodeString(inv.Tree)
		if err != nil {
			logrus.Errorf("[AGENT] Failed to base64 decode Tree bytes: %v", err)
			return
		}

		c.mu.RLock()
		name := c.name
		grpcClient := c.grpcClient
		clientIP := c.clientIP
		c.mu.RUnlock()

		_, err = grpcClient.JoinGroup(context.Background(), &pb.JoinGroupReq{
			ClientId: name, GroupId: env.GroupID, WelcomeBytes: wBytes, TreeBytes: tBytes,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to process join: %v", name, err)
			return
		}

		c.mu.Lock()
		c.groupEpochs[env.GroupID] = inv.Epoch
		c.mu.Unlock()

		secret, err := c.GetSharedSecret(env.GroupID)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after join: %v", name, err)
			return
		}

		actionMsg := fmt.Sprintf("Joined Group %s!", env.GroupID)
		c.handleSecretUpdate(env.GroupID, actionMsg, inv.Epoch, secret, clientIP, env.IPs)

		// CHANGED: We successfully consumed a KeyPackage to join this group.
		// Immediately generate and push a new one to the broker so we don't run out.
		go c.generateAndUploadKP()

	case "commit":
		c.processCommit(env.GroupID, env)

	case "update_request":
		var req map[string]string
		json.Unmarshal(env.Data, &req)

		c.mu.RLock()
		name := c.name
		serverURL := c.serverURL
		grpcClient := c.grpcClient
		clientIP := c.clientIP
		currentEpoch := c.groupEpochs[env.GroupID]
		members := append([]string(nil), c.groupMembers[env.GroupID]...)
		c.mu.RUnlock()

		logrus.Infof("[%s] Orchestrator mandated Key Rotation (Self-Update) for Group %s\n", name, env.GroupID)

		res, err := grpcClient.SelfUpdate(context.Background(), &pb.SelfUpdateReq{
			ClientId: name, GroupId: env.GroupID,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to self-update: %v", name, err)
			return
		}

		for _, member := range members {
			if member != name {
				sendMsg(serverURL, member, "commit", name, currentEpoch, env.GroupID, res.CommitBytes)
			}
		}

		c.mu.Lock()
		c.groupEpochs[env.GroupID] = currentEpoch + 1
		c.mu.Unlock()

		secret, err := c.GetSharedSecret(env.GroupID)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after key rotation: %v", name, err)
			return
		}

		c.handleSecretUpdate(env.GroupID, "Key-rotation", currentEpoch+1, secret, clientIP, env.IPs)
	}
}
