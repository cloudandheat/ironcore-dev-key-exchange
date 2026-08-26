package server

import (
	"encoding/json"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

type Envelope struct {
	Type    string `json:"Type"`
	From    string `json:"From"`
	Epoch   uint64 `json:"Epoch"`
	GroupID string `json:"GroupID"`
	Data    []byte `json:"Data"`
	IPs     string `json:"IPs,omitempty"`
}

type Subscriber struct {
	User string
	IP   string
}

type GroupInfo struct {
	Initiator string
	GroupID   string
	VNI       uint32
}

type AddRequest struct {
	User    string `json:"user"`
	GroupID string `json:"group_id"`
}

type BrokerResp struct {
	Status  string `json:"status"`
	GroupID string `json:"group_id"`
}

type ServerImpl struct {
	mu            sync.RWMutex
	mailboxes     map[string]chan Envelope
	keyPackages   map[string][]byte
	subscriptions map[uint32][]Subscriber
	groups        map[uint32]*GroupInfo
	groupIDToVNI  map[string]uint32
}

func NewServer() *ServerImpl {
	return &ServerImpl{
		mailboxes:     make(map[string]chan Envelope),
		keyPackages:   make(map[string][]byte),
		subscriptions: make(map[uint32][]Subscriber),
		groups:        make(map[uint32]*GroupInfo),
		groupIDToVNI:  make(map[string]uint32),
	}
}

func (s *ServerImpl) getMailbox(user string) chan Envelope {
	if s.mailboxes[user] == nil {
		s.mailboxes[user] = make(chan Envelope, 1000)
	}
	return s.mailboxes[user]
}

func (s *ServerImpl) sendHandler(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	data, _ := io.ReadAll(r.Body)
	epoch, _ := strconv.ParseUint(r.URL.Query().Get("epoch"), 10, 64)

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
		if msg.Type == "invite_payload" || msg.Type == "commit" || msg.Type == "add_request" || msg.Type == "remove_request" {
			s.mu.RLock()
			vni, ok := s.groupIDToVNI[msg.GroupID]
			if ok {
				var ips []string
				for _, sub := range s.subscriptions[vni] {
					ips = append(ips, sub.IP)
				}
				msg.IPs = strings.Join(ips, ",")
			}
			s.mu.RUnlock()
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(msg)

	case <-time.After(20 * time.Second):
		w.WriteHeader(http.StatusNoContent)
	}
}

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
	idInt, _ := strconv.ParseUint(r.URL.Query().Get("id"), 10, 32)
	id := uint32(idInt)
	ip := r.URL.Query().Get("ip")

	s.mu.Lock()
	s.subscriptions[id] = append(s.subscriptions[id], Subscriber{User: user, IP: ip})

	var group *GroupInfo
	var isCreator bool

	if s.groups[id] == nil {
		groupID := strconv.FormatUint(uint64(rand.Uint32()), 10)
		group = &GroupInfo{Initiator: user, GroupID: groupID, VNI: id}
		s.groups[id] = group
		s.groupIDToVNI[groupID] = id
		isCreator = true
	} else {
		group = s.groups[id]
		isCreator = false
	}
	s.mu.Unlock()

	if isCreator {
		logrus.Infof("----------------- [Broker] User '%s' is first on VNI %d, created Group %s\n", user, id, group.GroupID)
		json.NewEncoder(w).Encode(BrokerResp{Status: "created", GroupID: group.GroupID})
		return
	}

	logrus.Infof("----------------- [Broker] Requesting '%s' to invite '%s' to VNI %d\n", group.Initiator, user, id)
	req, _ := json.Marshal(AddRequest{User: user, GroupID: group.GroupID})

	s.mu.Lock()
	ch := s.getMailbox(group.Initiator)
	s.mu.Unlock()

	ch <- Envelope{Type: "add_request", From: "broker", GroupID: group.GroupID, Data: req}

	json.NewEncoder(w).Encode(BrokerResp{Status: "joined", GroupID: group.GroupID})
}

func (s *ServerImpl) handleUnsubscribe(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	idInt, _ := strconv.ParseUint(r.URL.Query().Get("id"), 10, 32)
	id := uint32(idInt)

	s.mu.Lock()
	var newSubs []Subscriber
	for _, sub := range s.subscriptions[id] {
		if sub.User != user {
			newSubs = append(newSubs, sub)
		}
	}
	s.subscriptions[id] = newSubs
	group := s.groups[id]
	s.mu.Unlock()

	if group != nil {
		initiator := group.Initiator
		if initiator == user {
			s.mu.RLock()
			if len(s.subscriptions[id]) > 0 {
				initiator = s.subscriptions[id][0].User
			}
			s.mu.RUnlock()
		}

		logrus.Infof("----------------- [Broker] User '%s' unsubscribed from VNI %d. Mandating %s to issue remove commit.\n", user, id, initiator)
		req, _ := json.Marshal(map[string]string{"user": user, "group_id": group.GroupID})

		s.mu.Lock()
		ch := s.getMailbox(initiator)
		s.mu.Unlock()

		ch <- Envelope{Type: "remove_request", From: "broker", GroupID: group.GroupID, Data: req}
	}
	w.WriteHeader(http.StatusOK)
}

// Add this method to ServerImpl
func (s *ServerImpl) startKeyRotationLoop() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		s.mu.Lock()
		var mandates []struct{ user, group string }

		// Find one member per active group to mandate the update
		for _, group := range s.groups {
			if subs, ok := s.subscriptions[group.VNI]; ok && len(subs) > 0 {
				// Just pick the first available subscriber in the group to execute the rotation
				targetUser := subs[0].User
				mandates = append(mandates, struct{ user, group string }{targetUser, group.GroupID})
			}
		}

		// Dispatch the mandates
		for _, m := range mandates {
			logrus.Infof("----------------- [Broker] Triggering 60s key rotation. Mandating %s to update Group %s", m.user, m.group)
			req, _ := json.Marshal(map[string]string{"group_id": m.group})
			ch := s.getMailbox(m.user)
			ch <- Envelope{Type: "update_request", From: "broker", GroupID: m.group, Data: req}
		}
		s.mu.Unlock()
	}
}

func (s *ServerImpl) Start(port string) error {
	logrus.Infof("----------------- [Broker] start MLS server")

	mux := http.NewServeMux()
	mux.HandleFunc("/send", s.sendHandler)
	mux.HandleFunc("/poll", s.pollHandler)
	mux.HandleFunc("/upload_kp", s.uploadKP)
	mux.HandleFunc("/get_kp", s.getKP)
	mux.HandleFunc("/subscribe", s.handleSubscribe)
	mux.HandleFunc("/unsubscribe", s.handleUnsubscribe)

	// Start the asynchronous rotation thread
	// TODO: fix it: group creator is not updated
	// go s.startKeyRotationLoop()

	return http.ListenAndServe(port, mux)
}
