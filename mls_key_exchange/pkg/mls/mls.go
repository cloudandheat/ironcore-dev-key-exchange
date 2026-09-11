// client.go
package mls

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	pb "github.com/cloudandheat/ironcore-dev-key-exchange/proto"
	dpdkproto "github.com/ironcore-dev/dpservice/go/dpservice-go/proto"

	// dpservice_api "github.com/ironcore-dev/dpservice/go/dpservice-go/api"
	dpdkclient "github.com/ironcore-dev/dpservice/go/dpservice-go/client"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Envelope struct {
	Type  string `json:"Type"`
	From  string `json:"From"`
	Epoch uint64 `json:"Epoch"`
	VNI   uint32 `json:"VNI"`
	Data  []byte `json:"Data"`
	IPs   string `json:"IPs"`
}

type InvitePayload struct {
	Welcome string `json:"welcome"`
	Tree    string `json:"tree"`
	Epoch   uint64 `json:"epoch"`
}

type AgentImpl struct {
	pb.UnimplementedAgentServiceServer
	mu           sync.RWMutex
	name         string
	serverURL    string
	clientPrefix string
	grpcClient   pb.MlsServiceClient
	dpdkClient   dpdkclient.Client

	groupKeyReady map[uint32]bool

	groupMembers map[uint32][]string
	groupEpochs  map[uint32]uint64
	commitBuffer map[uint32]map[uint64]Envelope
}

func NewAgent() *AgentImpl {
	return &AgentImpl{
		groupKeyReady: make(map[uint32]bool),
		groupMembers:  make(map[uint32][]string),
		groupEpochs:   make(map[uint32]uint64),
		commitBuffer:  make(map[uint32]map[uint64]Envelope),
	}
}

type DpServiceClient struct {
	client dpdkproto.DPDKironcoreClient
	conn   *grpc.ClientConn
}

func NewDpServiceClient(targetURL string) (*DpServiceClient, error) {
	conn, err := grpc.NewClient(targetURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to dpservice at %s: %v", targetURL, err)
	}

	return &DpServiceClient{
		client: dpdkproto.NewDPDKironcoreClient(conn),
		conn:   conn,
	}, nil
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

	dpserviceAddr := "127.0.0.1:1337"

	logrus.Info("init grpc to dpservice")

	conn, err := grpc.NewClient(dpserviceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logrus.Fatalf("unable create dpdk client: %s", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logrus.Fatalf("unable to close dpdk connection: %s", err)
		}
	}()
	logrus.Info("init grpc to dpservice done")

	dpdkProtoClient := dpdkproto.NewDPDKironcoreClient(conn)
	a.dpdkClient = dpdkclient.NewClient(dpdkProtoClient)
	logrus.Info("init dpservice-client")

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

func sendMsg(serverURL, to, msgType, from string, epoch uint64, vni uint32, data []byte) {
	url := fmt.Sprintf("%s/send?to=%s&type=%s&from=%s&epoch=%d&vni=%d", serverURL, to, msgType, from, epoch, vni)
	http.Post(url, "application/octet-stream", bytes.NewBuffer(data))
}

func (c *AgentImpl) sendAck(epoch uint64, vni uint32) {
	c.mu.RLock()
	serverURL := c.serverURL
	name := c.name
	c.mu.RUnlock()

	url := fmt.Sprintf("%s/ack?user=%s&vni=%d&epoch=%d", serverURL, name, vni, epoch)
	go func() {
		resp, err := http.Get(url)
		if err != nil {
			logrus.Errorf("[%s] Failed to send ACK for epoch %d: %v", name, epoch, err)
		} else {
			resp.Body.Close()
		}
	}()
}

func trimIPv6(ip string) string {
	if strings.HasSuffix(ip, ":1") {
		return ip[:len(ip)-1]
	}
	if strings.HasSuffix(ip, "/64") {
		return ip[:len(ip)-3]
	}
	return ip
}

func BytesToHex(data []byte) string {
	return hex.EncodeToString(data)
}

func (c *AgentImpl) handleSecretUpdate(vni uint32, action string, epoch uint64, secret []byte, ownIP string, vniIPs string) {
	c.mu.RLock()
	name := c.name
	c.mu.RUnlock()

	logrus.Infof("[%s] %s", name, action)
	ownPrefix, err1 := netip.ParsePrefix(ownIP)
	ips := strings.Split(vniIPs, ",")

	for _, peerIP := range ips {
		peerIP = strings.TrimSpace(peerIP)
		if peerIP == "" || peerIP == ownIP {
			continue
		}

		peerPrefix, err2 := netip.ParsePrefix(peerIP)
		var lower, higher string

		if err1 == nil && err2 == nil {
			if ownPrefix.Addr().Compare(peerPrefix.Addr()) < 0 {
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

		contextString := fmt.Sprintf("%d:%s:%s:%d", vni, lower, higher, epoch)

		h := fnv.New32a()
		h.Write([]byte(contextString))
		SPI := h.Sum32()

		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(contextString))
		secureHash := mac.Sum(nil)
		salt := secureHash[:4]

		SPI = vni

		logrus.Infof("-------------Debug-output")
		logrus.Infof("vni: %d", vni)
		logrus.Infof("SPI: %d", SPI)
		logrus.Infof("salt: %x", salt)
		logrus.Infof("target-prefix: %s", peerIP)
		logrus.Infof("own-prefix: %s", ownIP)
		//logrus.Infof("secret: %x", secret)

		//======================================================================================================
		// Workaround for the moment to enable encryption for all interfaces of the VNI
		// TODO: handle by metalnet network-interface controller
		interfaceList, err := c.dpdkClient.ListInterfaces(context.Background())
		if err != nil {
			fmt.Errorf("error listing interfaces: %w", err)
			return
		}
		for _, iface := range interfaceList.Items {
			if iface.Spec.VNI == vni {
				_, err := c.dpdkClient.EnableInterfaceEncryption(context.Background(), iface.ID)
				if err != nil {
					fmt.Errorf("error enabling interface encryption: %w", err)
					return
				}
			}
		}
		//======================================================================================================

		peerIPAddr, err := netip.ParseAddr(trimIPv6(peerIP))
		if err != nil {
			logrus.Errorf("Failed to parse peer-IP %s with error: %s", peerIP, err)
			return
		}

		ownIPAddr, err := netip.ParseAddr(trimIPv6(ownIP))
		if err != nil {
			logrus.Errorf("Failed to parse own-IP %s with error: %s", ownIP, err)
			return
		}

		logrus.Infof("create egress SA")

		_, err = c.dpdkClient.CreateSecurityAssociation(context.Background(), &dpservice_api.SecurityAssociation{
			TypeMeta: dpservice_api.TypeMeta{Kind: dpservice_api.SecurityAssociationKind},
			SecurityAssociationMeta: dpservice_api.SecurityAssociationMeta{
				Spi:         SPI,
				Vni:         vni,
				Direction:   "egress",
				SrcUnderlay: &ownIPAddr,
				DstUnderlay: &peerIPAddr,
			},
			Spec: dpservice_api.SecurityAssociationSpec{
				Algorithm:    "aes-256-gcm",
				Key:          BytesToHex(secret),
				Salt:         BytesToHex(salt),
				ReplayWindow: 0,
				Esn:          true,
			},
		})
		if err != nil {
			logrus.Errorf("unable to get create egress sa: %s", err)
			return
		}

		logrus.Infof("create ingress SA")

		_, err = c.dpdkClient.CreateSecurityAssociation(context.Background(), &dpservice_api.SecurityAssociation{
			TypeMeta: dpservice_api.TypeMeta{Kind: dpservice_api.SecurityAssociationKind},
			SecurityAssociationMeta: dpservice_api.SecurityAssociationMeta{
				Spi:         SPI,
				Vni:         vni,
				Direction:   "ingress",
				SrcUnderlay: &peerIPAddr,
				DstUnderlay: &ownIPAddr,
			},
			Spec: dpservice_api.SecurityAssociationSpec{
				Algorithm:    "aes-256-gcm",
				Key:          BytesToHex(secret),
				Salt:         BytesToHex(salt),
				ReplayWindow: 1000,
				Esn:          true,
			},
		})
		if err != nil {
			logrus.Errorf("unable to get create ingress sa: %s", err)
			return
		}

		c.mu.Lock()
		logrus.Infof("set VNI to ready: %d", vni)
		c.groupKeyReady[vni] = true
		c.mu.Unlock()
	}
}

func (c *AgentImpl) Init(ctx context.Context, req *pb.AgentInitReq) (*pb.AgentEmpty, error) {
	logrus.Infof("Init Agent")

	serverAddress := os.Getenv("MLS_SERVER_ADDRESS")
	grpcURL := os.Getenv("RUST_GRPC_URL")

	conn, err := grpc.NewClient(grpcURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to grpc: %v", err)
	}
	grpcClient := pb.NewMlsServiceClient(conn)

	c.mu.Lock()
	c.name = req.ClientName
	c.serverURL = serverAddress
	c.clientPrefix = req.ClientPrefix
	c.grpcClient = grpcClient
	c.mu.Unlock()

	_, err = grpcClient.GenerateCredential(context.Background(), &pb.GenerateReq{ClientId: req.ClientName})
	if err != nil {
		return nil, fmt.Errorf("failed to generate credential: %v", err)
	}

	for i := 0; i < 10; i++ {
		c.generateAndUploadKP()
	}

	c.startListener()
	return &pb.AgentEmpty{}, nil
}

func (c *AgentImpl) Subscribe(ctx context.Context, req *pb.AgentSubscribeReq) (*pb.AgentEmpty, error) {
	c.mu.RLock()
	name := c.name
	serverURL := c.serverURL
	clientPrefix := c.clientPrefix
	grpcClient := c.grpcClient
	c.mu.RUnlock()

	logrus.Infof("[%s] Subscribe VNI: %d", name, req.Vni)
	url := fmt.Sprintf("%s/subscribe?user=%s&id=%d&ip=%s", serverURL, name, req.Vni, clientPrefix)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("broker subscribe error: %v", err)
	}
	defer resp.Body.Close()

	var bResp struct {
		Status string `json:"status"`
		VNI    uint32 `json:"vni"`
	}
	json.NewDecoder(resp.Body).Decode(&bResp)

	if bResp.Status == "created" {
		logrus.Infof("[%s] Subscribed. Creating group for VNI %d", name, req.Vni)

		_, err := grpcClient.CreateGroup(context.Background(), &pb.CreateGroupReq{
			ClientId: name, GroupId: strconv.FormatUint(uint64(req.Vni), 10),
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to create group for VNI %d: %v", name, req.Vni, err)
			return nil, err
		}

		c.mu.Lock()
		c.groupMembers[req.Vni] = append(c.groupMembers[req.Vni], name)
		c.groupEpochs[req.Vni] = 1
		c.mu.Unlock()
	} else {
		logrus.Infof("[%s] Subscribed to VNI %d, waiting for invite", name, req.Vni)
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
	vni := req.Vni
	_, exists := c.groupMembers[vni]
	delete(c.groupKeyReady, vni)
	delete(c.groupMembers, vni)
	delete(c.groupEpochs, vni)
	delete(c.commitBuffer, vni)
	c.mu.Unlock()

	if exists {
		_, err := grpcClient.DropGroup(context.Background(), &pb.DropGroupReq{
			ClientId: name,
			GroupId:  strconv.FormatUint(uint64(vni), 10),
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to drop local group state: %v", name, err)
		} else {
			logrus.Infof("[%s] Successfully dropped VNI %d from local Rust state.", name, vni)
		}
	}

	return &pb.AgentEmpty{}, nil
}

func (c *AgentImpl) InviteMember(vni uint32, peerName string, ips string) {
	c.mu.RLock()
	name := c.name
	serverURL := c.serverURL
	grpcClient := c.grpcClient
	clientPrefix := c.clientPrefix
	currentEpoch := c.groupEpochs[vni]
	members := append([]string(nil), c.groupMembers[vni]...)
	c.mu.RUnlock()

	logrus.Infof("[%s] InviteMember to VNI: %d and peer: %s", name, vni, peerName)

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

	groupIdStr := strconv.FormatUint(uint64(vni), 10)
	res, err := grpcClient.InviteMembers(context.Background(), &pb.InviteReq{
		ClientId: name, GroupId: groupIdStr, TargetKpHex: string(peerPubKey),
	})
	if err != nil {
		logrus.Errorf("[%s] Failed to invite %s: %v", name, peerName, err)
		return
	}

	treeRes, err := grpcClient.SerializeTree(context.Background(), &pb.SerializeTreeReq{GroupId: groupIdStr})
	if err != nil {
		logrus.Errorf("[%s] Failed to serialize tree for VNI %d: %v", name, vni, err)
		return
	}

	inv := InvitePayload{
		Welcome: base64.StdEncoding.EncodeToString(res.WelcomeBytes),
		Tree:    base64.StdEncoding.EncodeToString(treeRes.TreeBytes),
		Epoch:   currentEpoch + 1,
	}
	invData, _ := json.Marshal(inv)

	sendMsg(serverURL, peerName, "invite_payload", name, currentEpoch+1, vni, invData)

	for _, member := range members {
		if member != name && member != peerName {
			sendMsg(serverURL, member, "commit", name, currentEpoch, vni, res.CommitBytes)
		}
	}

	c.mu.Lock()
	c.groupMembers[vni] = append(c.groupMembers[vni], peerName)
	c.groupEpochs[vni] = currentEpoch + 1
	c.mu.Unlock()

	secret, err := c.GetSharedSecret(vni)
	if err == nil {
		c.handleSecretUpdate(vni, "Tree Updated", currentEpoch+1, secret, clientPrefix, ips)
		c.sendAck(currentEpoch+1, vni)
	} else {
		logrus.Errorf("[%s] Failed to extract shared secret after invite: %v", name, err)
	}
}

func (c *AgentImpl) IsKeyReady(ctx context.Context, req *pb.AgentKeyReadyReq) (*pb.AgentKeyReadyRes, error) {
	c.mu.RLock()
	name := c.name
	readyStatus, exists := c.groupKeyReady[req.Vni]
	c.mu.RUnlock()

	logrus.Infof("[%s] IsKeyReady for vni: %d", name, req.Vni)

	if !exists {
		return &pb.AgentKeyReadyRes{IsReady: false}, nil
	}

	logrus.Infof("[%s] key-ready status for vni %d is: %t", name, req.Vni, readyStatus)

	return &pb.AgentKeyReadyRes{IsReady: readyStatus}, nil
}

func (c *AgentImpl) processCommit(vni uint32, env Envelope) {
	c.mu.RLock()
	expectedEpoch := c.groupEpochs[vni]
	name := c.name
	grpcClient := c.grpcClient
	clientPrefix := c.clientPrefix
	c.mu.RUnlock()

	if env.Epoch > expectedEpoch {
		c.mu.Lock()
		if c.commitBuffer[vni] == nil {
			c.commitBuffer[vni] = make(map[uint64]Envelope)
		}
		c.commitBuffer[vni][env.Epoch] = env
		c.mu.Unlock()
		return
	}

	if env.Epoch == expectedEpoch {
		groupIdStr := strconv.FormatUint(uint64(vni), 10)
		_, err := grpcClient.ProcessCommit(context.Background(), &pb.ProcessCommitReq{
			ClientId: name, GroupId: groupIdStr, CommitBytes: env.Data,
		})

		if err != nil {
			logrus.Errorf("[%s] Failed to process commit in epoch %d: %v", name, env.Epoch, err)
			return
		}

		c.mu.Lock()
		c.groupEpochs[vni] = expectedEpoch + 1
		c.mu.Unlock()

		secret, err := c.GetSharedSecret(vni)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after commit processing: %v", name, err)
			return
		}

		c.handleSecretUpdate(vni, "Tree Updated", expectedEpoch+1, secret, clientPrefix, env.IPs)
		c.sendAck(expectedEpoch+1, vni)

		c.mu.Lock()
		bufEnv, ok := c.commitBuffer[vni][expectedEpoch+1]
		if ok {
			delete(c.commitBuffer[vni], expectedEpoch+1)
		}
		c.mu.Unlock()

		if ok {
			c.processCommit(vni, bufEnv)
		}
	}
}

func (c *AgentImpl) GetSharedSecret(vni uint32) ([]byte, error) {
	c.mu.RLock()
	name := c.name
	grpcClient := c.grpcClient
	c.mu.RUnlock()

	res, err := grpcClient.ExportSharedSecret(context.Background(), &pb.ExportSecretReq{
		ClientId: name, GroupId: strconv.FormatUint(uint64(vni), 10), Label: "default-app-secret",
	})
	if err != nil {
		return nil, err
	}
	return res.SecretBytes, nil
}

func (c *AgentImpl) handleEvent(env Envelope) {
	switch env.Type {
	case "epoch_ready":
		c.mu.Lock()
		logrus.Infof("[%s] Received epoch_ready for VNI %d, Epoch %d. All peers have provisioned the datapath.", c.name, env.VNI, env.Epoch)
		c.mu.Unlock()

	case "add_request":
		var req struct {
			User string `json:"user"`
			VNI  uint32 `json:"vni"`
		}
		json.Unmarshal(env.Data, &req)

		c.mu.RLock()
		name := c.name
		c.mu.RUnlock()

		logrus.Infof("[%s] Orchestrator mandated invite of %s to VNI %d\n", name, req.User, env.VNI)
		c.InviteMember(env.VNI, req.User, env.IPs)

	case "remove_request":
		var req struct {
			User string `json:"user"`
			VNI  uint32 `json:"vni"`
		}
		json.Unmarshal(env.Data, &req)
		target := req.User

		c.mu.RLock()
		name := c.name
		serverURL := c.serverURL
		grpcClient := c.grpcClient
		clientPrefix := c.clientPrefix
		currentEpoch := c.groupEpochs[env.VNI]
		members := append([]string(nil), c.groupMembers[env.VNI]...)
		c.mu.RUnlock()

		logrus.Infof("[%s] Orchestrator mandated removal of %s from VNI %d\n", name, target, env.VNI)

		res, err := grpcClient.RemoveMember(context.Background(), &pb.RemoveReq{
			ClientId: name, GroupId: strconv.FormatUint(uint64(env.VNI), 10), TargetClientId: target,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to remove %s: %v", name, target, err)
			return
		}

		for _, member := range members {
			if member != name && member != target {
				sendMsg(serverURL, member, "commit", name, currentEpoch, env.VNI, res.CommitBytes)
			}
		}

		c.mu.Lock()
		var newMembers []string
		for _, m := range c.groupMembers[env.VNI] {
			if m != target {
				newMembers = append(newMembers, m)
			}
		}
		c.groupMembers[env.VNI] = newMembers
		c.groupEpochs[env.VNI] = currentEpoch + 1
		c.mu.Unlock()

		secret, err := c.GetSharedSecret(env.VNI)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after member removal: %v", name, err)
			return
		}

		actionMsg := fmt.Sprintf("Tree Updated. REMOVED %s", target)
		c.handleSecretUpdate(env.VNI, actionMsg, currentEpoch+1, secret, clientPrefix, env.IPs)
		c.sendAck(currentEpoch+1, env.VNI)

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
		clientPrefix := c.clientPrefix
		c.mu.RUnlock()

		_, err = grpcClient.JoinGroup(context.Background(), &pb.JoinGroupReq{
			ClientId: name, GroupId: strconv.FormatUint(uint64(env.VNI), 10), WelcomeBytes: wBytes, TreeBytes: tBytes,
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to process join: %v", name, err)
			return
		}

		c.mu.Lock()
		c.groupEpochs[env.VNI] = inv.Epoch
		c.mu.Unlock()

		secret, err := c.GetSharedSecret(env.VNI)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after join: %v", name, err)
			return
		}

		actionMsg := fmt.Sprintf("Joined VNI %d!", env.VNI)
		c.handleSecretUpdate(env.VNI, actionMsg, inv.Epoch, secret, clientPrefix, env.IPs)
		c.sendAck(inv.Epoch, env.VNI)
		go c.generateAndUploadKP()

	case "commit":
		c.processCommit(env.VNI, env)

	case "update_request":
		c.mu.RLock()
		name := c.name
		serverURL := c.serverURL
		grpcClient := c.grpcClient
		clientPrefix := c.clientPrefix
		currentEpoch := c.groupEpochs[env.VNI]
		members := append([]string(nil), c.groupMembers[env.VNI]...)
		c.mu.RUnlock()

		logrus.Infof("[%s] Orchestrator mandated Key Rotation (Self-Update) for VNI %d\n", name, env.VNI)

		res, err := grpcClient.SelfUpdate(context.Background(), &pb.SelfUpdateReq{
			ClientId: name, GroupId: strconv.FormatUint(uint64(env.VNI), 10),
		})
		if err != nil {
			logrus.Errorf("[%s] Failed to self-update: %v", name, err)
			return
		}

		for _, member := range members {
			if member != name {
				sendMsg(serverURL, member, "commit", name, currentEpoch, env.VNI, res.CommitBytes)
			}
		}

		c.mu.Lock()
		c.groupEpochs[env.VNI] = currentEpoch + 1
		c.mu.Unlock()

		secret, err := c.GetSharedSecret(env.VNI)
		if err != nil {
			logrus.Errorf("[%s] Failed to extract shared secret after key rotation: %v", name, err)
			return
		}

		c.handleSecretUpdate(env.VNI, "Key-rotation", currentEpoch+1, secret, clientPrefix, env.IPs)
		c.sendAck(currentEpoch+1, env.VNI)
	}
}
