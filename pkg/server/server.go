package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type Envelope struct {
	Type    string `json:"Type"`
	From    string `json:"From"`
	Epoch   uint64 `json:"Epoch"`
	GroupID string `json:"GroupID"`
	Data    []byte `json:"Data"` // Go's JSON automatically converts []byte to Base64
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

type ServerImpl struct {
	mu            sync.RWMutex
	mailboxes     map[string]chan Envelope
	keyPackages   map[string][]byte
	subscriptions map[uint32][]string
	groups        map[uint32][]GroupInfo
}

func NewServer() *ServerImpl {
	return &ServerImpl{
		mailboxes:     make(map[string]chan Envelope),
		keyPackages:   make(map[string][]byte),
		subscriptions: make(map[uint32][]string),
		groups:        make(map[uint32][]GroupInfo),
	}
}

func (s *ServerImpl) getMailbox(user string) chan Envelope {
	if s.mailboxes[user] == nil {
		s.mailboxes[user] = make(chan Envelope, 1000)
	}
	return s.mailboxes[user]
}

// --- Standard Messaging Routes ---

func (s *ServerImpl) sendHandler(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	data, _ := io.ReadAll(r.Body)

	epochStr := r.URL.Query().Get("epoch")
	epoch, _ := strconv.ParseUint(epochStr, 10, 64)

	env := Envelope{
		Type:    r.URL.Query().Get("type"),
		From:    r.URL.Query().Get("from"),
		Epoch:   epoch,
		GroupID: r.URL.Query().Get("group"),
		Data:    data,
	}

	s.mu.Lock()
	ch := s.getMailbox(to)
	s.mu.Unlock()

	ch <- env
	w.WriteHeader(http.StatusOK)
}

func (s *ServerImpl) pollHandler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")

	s.mu.Lock()
	ch := s.getMailbox(user)
	s.mu.Unlock()

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

func (s *ServerImpl) uploadKP(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	data, _ := io.ReadAll(r.Body)

	s.mu.Lock()
	s.keyPackages[user] = data
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (s *ServerImpl) getKP(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")

	s.mu.RLock()
	data, exists := s.keyPackages[user]
	s.mu.RUnlock()

	if !exists {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Write(data)
}

func (s *ServerImpl) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	idStr := r.URL.Query().Get("id")
	idInt, _ := strconv.ParseUint(idStr, 10, 32)
	id := uint32(idInt)

	s.mu.Lock()
	s.subscriptions[id] = append(s.subscriptions[id], user)

	var groupsToNotify []GroupInfo
	groupsToNotify = append(groupsToNotify, s.groups[id]...)
	s.mu.Unlock()

	logrus.Infof("[Broker] User '%s' subscribed to vni %d\n", user, id)

	// Process notifications strictly outside the lock
	for _, g := range groupsToNotify {
		if g.Initiator != user {
			logrus.Infof("[Broker] Automatically requesting %s to invite new subscriber %s to group %s\n", g.Initiator, user, g.GroupID)
			req, _ := json.Marshal(AddRequest{User: user, GroupID: g.GroupID})

			s.mu.Lock()
			ch := s.getMailbox(g.Initiator)
			s.mu.Unlock()

			ch <- Envelope{
				Type: "add_request", From: "broker", Data: req,
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *ServerImpl) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	idStr := r.URL.Query().Get("id")
	groupName := r.URL.Query().Get("name")
	groupID := r.URL.Query().Get("vni")

	idInt, _ := strconv.ParseUint(idStr, 10, 32)
	id := uint32(idInt)

	s.mu.Lock()
	s.groups[id] = append(s.groups[id], GroupInfo{Initiator: user, GroupName: groupName, GroupID: groupID})

	var subsToNotify []string
	subsToNotify = append(subsToNotify, s.subscriptions[id]...)
	s.mu.Unlock()

	logrus.Infof("[Broker] Group '%s' created on vni %d by %s\n", groupName, id, user)

	// Notify strictly outside the lock
	for _, subUser := range subsToNotify {
		if subUser != user {
			req, _ := json.Marshal(AddRequest{User: subUser, GroupID: groupID})

			s.mu.Lock()
			ch := s.getMailbox(user)
			s.mu.Unlock()

			ch <- Envelope{
				Type: "add_request", From: "broker", Data: req,
			}
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *ServerImpl) Start(port string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/send", s.sendHandler)
	mux.HandleFunc("/poll", s.pollHandler)
	mux.HandleFunc("/upload_kp", s.uploadKP)
	mux.HandleFunc("/get_kp", s.getKP)
	mux.HandleFunc("/subscribe", s.handleSubscribe)
	mux.HandleFunc("/create_group", s.handleCreateGroup)

	return http.ListenAndServe(port, mux)
}
