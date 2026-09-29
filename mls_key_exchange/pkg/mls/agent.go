// The key-exchange agent: its state, startup and self-initialization from dpservice.
package mls

import (
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	pb "github.com/cloudandheat/ironcore-dev-key-exchange/proto"
	dpdkclient "github.com/ironcore-dev/dpservice/go/dpservice-go/client"
	dpdkproto "github.com/ironcore-dev/dpservice/go/dpservice-go/proto"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AgentImpl struct {
	pb.UnimplementedAgentServiceServer

	// mu serializes all work of the agent: gRPC calls from metalnet and events from the server
	mu           sync.Mutex
	name         string
	serverURL    string
	clientPrefix string
	ownPrefix    netip.Addr
	grpcClient   pb.MlsServiceClient
	dpdkClient   dpdkclient.Client
	httpClient   *http.Client
	bootID       string
	listening    bool

	subscribed   map[uint32]bool
	commitBuffer map[uint32]map[uint64]Envelope
	rounds       map[uint32]*roundState
	pairs        map[uint32]map[netip.Addr]*pairState

	readyMu       sync.RWMutex
	groupKeyReady map[uint32]bool
}

// NewAgent creates an agent with empty state. It does nothing until Start is called.
func NewAgent() *AgentImpl {
	return &AgentImpl{
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		subscribed:    make(map[uint32]bool),
		commitBuffer:  make(map[uint32]map[uint64]Envelope),
		rounds:        make(map[uint32]*roundState),
		pairs:         make(map[uint32]map[netip.Addr]*pairState),
		groupKeyReady: make(map[uint32]bool),
	}
}

// Start runs the agent: it connects to the local dpservice, starts the self-initialization from
// dpservice in the background and serves the gRPC API for metalnet on the given address. It blocks
// for the whole lifetime of the agent.
func (a *AgentImpl) Start(port string) {
	logrus.Infof("Start Key-exchange")

	lis, err := net.Listen("tcp", port)
	if err != nil {
		logrus.Fatalf("Failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterAgentServiceServer(grpcServer, a)

	dpserviceAddr := os.Getenv("DPSERVICE_ADDRESS")
	if dpserviceAddr == "" {
		dpserviceAddr = "127.0.0.1:1337"
	}

	logrus.Infof("Init grpc to dpservice")

	conn, err := grpc.NewClient(dpserviceAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		logrus.Fatalf("unable create dpdk client: %s", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			logrus.Fatalf("unable to close dpdk connection: %s", err)
		}
	}()

	dpdkProtoClient := dpdkproto.NewDPDKironcoreClient(conn)
	a.dpdkClient = dpdkclient.NewClient(dpdkProtoClient)
	logrus.Info("init dpservice-client")

	// Without metalnet calling Init again after a restart, the agent initializes itself with
	// everything it needs from dpservice.
	go a.autoInit()

	logrus.Infof("Starting Go Client Agent Daemon on %s", port)
	if err := grpcServer.Serve(lis); err != nil {
		logrus.Fatalf("Failed to serve: %v", err)
	}
}

// autoInit initializes the agent from dpservice, so a restarted agent recovers without metalnet
// calling Init again. It waits until dpservice has interfaces, which tell the underlay prefix of
// this host, and stops as soon as the agent is initialized, either by itself or by metalnet. A
// fresh host without interfaces has nothing to recover, so there it simply waits for metalnet to
// call Init.
func (a *AgentImpl) autoInit() {
	for {
		a.mu.Lock()
		initialized := a.name != ""
		a.mu.Unlock()
		if initialized {
			return
		}

		prefix, err := a.underlayFromDpservice()
		if err != nil {
			logrus.Debugf("Auto-init: no underlay prefix available yet: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		a.mu.Lock()
		if a.name == "" {
			logrus.Infof("Auto-init with underlay prefix %s from dpservice", prefix)
			err = a.initLocked(prefix)
		}
		a.mu.Unlock()
		if err == nil {
			return
		}
		logrus.Warnf("Auto-init failed, retrying: %v", err)
		time.Sleep(5 * time.Second)
	}
}

// setKeyReady sets or clears the flag, which IsKeyReady reports to metalnet for a VNI. The flag has
// its own lock, so IsKeyReady never has to wait for long-running work under a.mu.
func (a *AgentImpl) setKeyReady(vni uint32, ready bool) {
	a.readyMu.Lock()
	defer a.readyMu.Unlock()
	if ready {
		a.groupKeyReady[vni] = true
	} else {
		delete(a.groupKeyReady, vni)
	}
}
