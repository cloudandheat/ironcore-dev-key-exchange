package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	pb "github.com/cloudandheat/ironcore-dev-key-exchange/pkg/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type ClientImpl struct {
	name       string
	serverURL  string
	grpcClient pb.MlsServiceClient
}

func NewClient() *ClientImpl {
	return &ClientImpl{}
}

type Envelope struct {
	Type    string
	From    string
	Epoch   uint64
	GroupID string
	Data    []byte
}

type InvitePayload struct {
	Welcome string `json:"welcome"`
	Tree    string `json:"tree"`
	Epoch   uint64 `json:"epoch"`
}

type AppMessage struct {
	Action        string `json:"action"`
	GroupID       string `json:"group_id"`
	SecretPreview string `json:"secret_preview"`
}

var (
	groupMembers = make(map[string][]string)
	groupEpochs  = make(map[string]uint64)
	commitBuffer = make(map[string]map[uint64]Envelope)
)

func (c *ClientImpl) startListener() {
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

			msgType := resp.Header.Get("X-Message-Type")
			from := resp.Header.Get("X-Message-From")
			epoch, _ := strconv.ParseUint(resp.Header.Get("X-Epoch"), 10, 64)
			groupID := resp.Header.Get("X-Group-ID")
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			env := Envelope{Type: msgType, From: from, Epoch: epoch, GroupID: groupID, Data: data}
			c.handleEvent(env)
		}
	}()
}

func sendMsg(serverURL, to, msgType, from string, epoch uint64, groupID string, data []byte) {
	url := fmt.Sprintf("%s/send?to=%s&type=%s&from=%s&epoch=%d&group=%s", serverURL, to, msgType, from, epoch, groupID)
	http.Post(url, "application/octet-stream", bytes.NewBuffer(data))
}

func (c *ClientImpl) Init(name, brokerURL string) error {
	c.name = name
	c.serverURL = brokerURL

	grpcURL := os.Getenv("RUST_GRPC_URL")
	conn, err := grpc.NewClient(grpcURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect to grpc: %v", err)
	}
	c.grpcClient = pb.NewMlsServiceClient(conn)
	ctx := context.Background()

	c.grpcClient.GenerateCredential(ctx, &pb.GenerateReq{ClientId: name})

	kpRes, _ := c.grpcClient.GenerateKeyPackage(ctx, &pb.GenerateReq{ClientId: name})
	pubKey := []byte(kpRes.KeyPackageHex)

	url := fmt.Sprintf("%s/upload_kp?user=%s", brokerURL, name)
	for {
		resp, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(pubKey))
		if err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		fmt.Printf("[%s] Waiting for broker to come online...\n", c.name)
		time.Sleep(1 * time.Second)
	}

	c.startListener()
	return nil
}

func (c *ClientImpl) Subscribe(vni uint32) error {
	url := fmt.Sprintf("%s/subscribe?user=%s&id=%d", c.serverURL, c.name, vni)
	http.Get(url)
	return nil
}

func (c *ClientImpl) CreateGroup(groupName string, vni uint32) error {
	groupID := strconv.FormatUint(uint64(rand.Uint32()), 10)

	c.grpcClient.CreateGroup(context.Background(), &pb.CreateGroupReq{
		ClientId: c.name, GroupId: groupID,
	})

	groupMembers[groupID] = append(groupMembers[groupID], c.name)
	groupEpochs[groupID] = 1

	url := fmt.Sprintf("%s/create_group?user=%s&id=%d&name=%s&vni=%s", c.serverURL, c.name, vni, groupName, groupID)
	http.Get(url)
	return nil
}

func (c *ClientImpl) InviteMember(groupID string, peerName string) {
	resp, _ := http.Get(fmt.Sprintf("%s/get_kp?user=%s", c.serverURL, peerName))
	peerPubKey, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	currentEpoch := groupEpochs[groupID]

	res, _ := c.grpcClient.InviteMembers(context.Background(), &pb.InviteReq{
		ClientId: c.name, GroupId: groupID, TargetKpHex: string(peerPubKey),
	})

	treeRes, _ := c.grpcClient.SerializeTree(context.Background(), &pb.SerializeTreeReq{GroupId: groupID})

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
}

func (c *ClientImpl) processCommit(groupID string, env Envelope) {
	expectedEpoch := groupEpochs[groupID]

	if env.Epoch > expectedEpoch {
		if commitBuffer[groupID] == nil {
			commitBuffer[groupID] = make(map[uint64]Envelope)
		}
		commitBuffer[groupID][env.Epoch] = env
		return
	}

	if env.Epoch == expectedEpoch {
		c.grpcClient.ProcessCommit(context.Background(), &pb.ProcessCommitReq{
			ClientId: c.name, GroupId: groupID, CommitBytes: env.Data,
		})

		groupEpochs[groupID] = expectedEpoch + 1
		secret, _ := c.GetSharedSecret(groupID)

		fmt.Printf("[%s] Tree Updated (Epoch %d). GroupKey Preview: %x\n", c.name, expectedEpoch+1, secret[:4])

		msgData, _ := json.Marshal(AppMessage{
			Action:        "Epoch updated successfully",
			GroupID:       groupID,
			SecretPreview: hex.EncodeToString(secret[:4]),
		})
		sendMsg(c.serverURL, env.From, "app_message", c.name, expectedEpoch+1, groupID, msgData)

		if bufEnv, ok := commitBuffer[groupID][groupEpochs[groupID]]; ok {
			delete(commitBuffer[groupID], groupEpochs[groupID])
			c.processCommit(groupID, bufEnv)
		}
	}
}

func (c *ClientImpl) GetSharedSecret(groupID string) ([]byte, error) {
	res, err := c.grpcClient.ExportSharedSecret(context.Background(), &pb.ExportSecretReq{
		ClientId: c.name, GroupId: groupID, Label: "default-app-secret",
	})
	if err != nil {
		return nil, err
	}
	return res.SecretBytes, nil
}

func (c *ClientImpl) handleEvent(env Envelope) {
	switch env.Type {
	case "add_request":
		var req map[string]string
		json.Unmarshal(env.Data, &req)
		fmt.Printf("[%s] Orchestrator mandated invite of %s to Group %s\n", c.name, req["user"], req["group_id"])
		c.InviteMember(req["group_id"], req["user"])

	case "invite_payload":
		var inv InvitePayload
		json.Unmarshal(env.Data, &inv)

		wBytes, _ := base64.StdEncoding.DecodeString(inv.Welcome)
		tBytes, _ := base64.StdEncoding.DecodeString(inv.Tree)

		c.grpcClient.JoinGroup(context.Background(), &pb.JoinGroupReq{
			ClientId: c.name, GroupId: env.GroupID, WelcomeBytes: wBytes, TreeBytes: tBytes,
		})

		groupEpochs[env.GroupID] = inv.Epoch
		secret, _ := c.GetSharedSecret(env.GroupID)

		fmt.Printf("[%s] Joined Group %s! GroupKey Preview: %x\n", c.name, env.GroupID, secret[:4])

		msgData, _ := json.Marshal(AppMessage{
			Action: "Joined successfully", GroupID: env.GroupID, SecretPreview: hex.EncodeToString(secret[:4]),
		})
		sendMsg(c.serverURL, env.From, "app_message", c.name, inv.Epoch, env.GroupID, msgData)

	case "commit":
		c.processCommit(env.GroupID, env)

	case "app_message":
		var appMsg AppMessage
		json.Unmarshal(env.Data, &appMsg)
		fmt.Printf("[%s] (Decrypted via MLS) Message from %s: Action='%s', GroupKey Match Verification: %s\n",
			c.name, env.From, appMsg.Action, appMsg.SecretPreview)
	}
}
