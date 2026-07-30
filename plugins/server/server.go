package main

// #cgo LDFLAGS: -L/build/rust_mls_bridge/target/release -lrust_mls_bridge -lm -ldl -lpthread

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	shared "github.com/cloudandheat/ironcore-dev-key-exchange/plugins/shared"

	"github.com/sirupsen/logrus"
)

type ServerImpl struct{}

type Envelope struct {
	Type    string `json:"Type"`
	From    string `json:"From"`
	Epoch   uint64 `json:"Epoch"`
	GroupID string `json:"GroupID"`
	Data    []byte `json:"Data"`
}

type GroupInfo struct {
	Initiator string
	GroupName string
	GroupID   string
}

type AddRequest struct {
	User    string `json:"user"`
	GroupID string `json:"group_id"`
}

var (
	mailboxes     = make(map[string]chan Envelope)
	keyPackages   = make(map[string][]byte)
	subscriptions = make(map[uint32][]string)
	groups        = make(map[uint32][]GroupInfo)
	serverMu      sync.Mutex
)

func getMailbox(user string) chan Envelope {
	if mailboxes[user] == nil {
		mailboxes[user] = make(chan Envelope, 100)
	}
	return mailboxes[user]
}

// --- Standard Messaging Routes ---

func sendHandler(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	data, _ := io.ReadAll(r.Body)

	epochStr := r.URL.Query().Get("epoch")
	epoch, _ := strconv.ParseUint(epochStr, 10, 64)

	serverMu.Lock()
	getMailbox(to) <- Envelope{
		Type:    r.URL.Query().Get("type"),
		From:    r.URL.Query().Get("from"),
		Epoch:   epoch,
		GroupID: r.URL.Query().Get("group"),
		Data:    data,
	}
	serverMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func pollHandler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")

	serverMu.Lock()
	ch := getMailbox(user)
	serverMu.Unlock()

	select {
	case <-r.Context().Done():
		return

	case msg := <-ch:
		w.Header().Set("X-Message-Type", msg.Type)
		w.Header().Set("X-Message-From", msg.From)
		w.Header().Set("X-Epoch", strconv.FormatUint(msg.Epoch, 10))
		w.Header().Set("X-Group-ID", msg.GroupID)
		w.Write(msg.Data)

	case <-time.After(20 * time.Second):
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Pub/Sub & Key Management Routes ---

func uploadKP(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	data, _ := io.ReadAll(r.Body)
	serverMu.Lock()
	keyPackages[user] = data
	serverMu.Unlock()
}

func getKP(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	serverMu.Lock()
	data := keyPackages[user]
	serverMu.Unlock()
	w.Write(data)
}

func handleSubscribe(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	idStr := r.URL.Query().Get("id")
	idInt, _ := strconv.ParseUint(idStr, 10, 32)
	id := uint32(idInt)

	serverMu.Lock()
	defer serverMu.Unlock()

	subscriptions[id] = append(subscriptions[id], user)
	logrus.WithFields(nil).Infof("[MLS-Broker] User '%s' subscribed to vni %d\n", user, id)
	// If there are already groups on this vni, tell their initiators to invite the new user
	for _, g := range groups[id] {
		if g.Initiator != user {
			logrus.WithFields(nil).Infof("[MLS-Broker] Automatically requesting %s to invite new subscriber %s to group %s\n", g.Initiator, user, g.GroupID)
			req, _ := json.Marshal(AddRequest{User: user, GroupID: g.GroupID})

			getMailbox(g.Initiator) <- Envelope{
				Type: "add_request", From: "broker", Data: req,
			}
		}
	}
}

func handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	idStr := r.URL.Query().Get("id")
	groupName := r.URL.Query().Get("name")
	groupID := r.URL.Query().Get("vni")

	idInt, _ := strconv.ParseUint(idStr, 10, 32)
	id := uint32(idInt)

	serverMu.Lock()
	defer serverMu.Unlock()

	groups[id] = append(groups[id], GroupInfo{Initiator: user, GroupName: groupName, GroupID: groupID})
	logrus.WithFields(nil).Infof("[MLS-Broker] Group '%s' created on vni %d by %s\n", groupName, id, user)
	// Notify the creator to invite all existing subscribers
	for _, subUser := range subscriptions[id] {
		if subUser != user {
			req, _ := json.Marshal(AddRequest{User: subUser, GroupID: groupID})
			getMailbox(user) <- Envelope{
				Type: "add_request", From: "broker", Data: req,
			}
		}
	}
}

func (s *ServerImpl) Start(port string) error {
	http.HandleFunc("/send", sendHandler)
	http.HandleFunc("/poll", pollHandler)
	http.HandleFunc("/upload_kp", uploadKP)
	http.HandleFunc("/get_kp", getKP)
	http.HandleFunc("/subscribe", handleSubscribe)
	http.HandleFunc("/create_group", handleCreateGroup)

	ret := http.ListenAndServe(port, nil)
	if ret != nil {
		logrus.WithFields(nil).Error("failed to start listener: ", ret)
	}

	return ret
}

var Plugin shared.ServerPlugin = &ServerImpl{}
