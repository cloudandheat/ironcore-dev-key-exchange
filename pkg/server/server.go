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
	keyPackages   map[string][][]byte
	subscriptions map[uint32][]Subscriber
	groups        map[uint32]*GroupInfo
	groupIDToVNI  map[string]uint32
}

func NewServer() *ServerImpl {
	return &ServerImpl{
		mailboxes:     make(map[string]chan Envelope),
		keyPackages:   make(map[string][][]byte),
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
	s.keyPackages[user] = append(s.keyPackages[user], data)
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

func (s *ServerImpl) getKP(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")

	s.mu.Lock()
	defer s.mu.Unlock()

	// If no KeyPackages are left, return 404 to tell the inviter to retry
	if len(s.keyPackages[user]) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// Pop the oldest KeyPackage from the queue
	data := s.keyPackages[user][0]
	s.keyPackages[user] = s.keyPackages[user][1:]

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

	initiator := group.Initiator
	groupID := group.GroupID
	var ch chan Envelope

	if !isCreator {
		ch = s.getMailbox(initiator)
	}
	s.mu.Unlock()

	if isCreator {
		logrus.Infof("[MLS-Broker] User '%s' is first on VNI %d, created Group %s\n", user, id, groupID)
		json.NewEncoder(w).Encode(BrokerResp{Status: "created", GroupID: groupID})
		return
	}

	logrus.Infof("[MLS-Broker] Requesting '%s' to invite '%s' to VNI %d\n", initiator, user, id)
	req, _ := json.Marshal(AddRequest{User: user, GroupID: groupID})
	ch <- Envelope{Type: "add_request", From: "broker", GroupID: groupID, Data: req}

	json.NewEncoder(w).Encode(BrokerResp{Status: "joined", GroupID: groupID})
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
	var initiator string
	var groupID string
	var ch chan Envelope

	if group != nil {
		groupID = group.GroupID
		if group.Initiator == user {
			if len(s.subscriptions[id]) > 0 {
				group.Initiator = s.subscriptions[id][0].User
			} else {
				group.Initiator = ""
			}
		}

		initiator = group.Initiator
		if initiator != "" {
			ch = s.getMailbox(initiator)
		}
	}
	s.mu.Unlock()

	if initiator != "" {
		logrus.Infof("[MLS-Broker] User '%s' unsubscribed from VNI %d. Mandating %s to issue remove commit.\n", user, id, initiator)
		req, _ := json.Marshal(map[string]string{"user": user, "group_id": groupID})
		ch <- Envelope{Type: "remove_request", From: "broker", GroupID: groupID, Data: req}
	}
	w.WriteHeader(http.StatusOK)
}

func (s *ServerImpl) startKeyRotationLoop() {
	ticker := time.NewTicker(60 * time.Second)
	for range ticker.C {
		s.mu.Lock()
		var mandates []struct {
			user  string
			group string
			ch    chan Envelope
		}

		for _, group := range s.groups {
			if subs, ok := s.subscriptions[group.VNI]; ok && len(subs) > 0 {
				targetUser := subs[0].User
				mandates = append(mandates, struct {
					user  string
					group string
					ch    chan Envelope
				}{
					user:  targetUser,
					group: group.GroupID,
					ch:    s.getMailbox(targetUser),
				})
			}
		}
		s.mu.Unlock()

		for _, m := range mandates {
			logrus.Infof("[MLS-Broker] Triggering 60s key rotation. Mandating %s to update Group %s", m.user, m.group)
			req, _ := json.Marshal(map[string]string{"group_id": m.group})
			m.ch <- Envelope{Type: "update_request", From: "broker", GroupID: m.group, Data: req}
		}
	}
}

func (s *ServerImpl) Start(port string) error {
	logrus.Infof("[MLS-Broker] start MLS server")

	mux := http.NewServeMux()
	mux.HandleFunc("/send", s.sendHandler)
	mux.HandleFunc("/poll", s.pollHandler)
	mux.HandleFunc("/upload_kp", s.uploadKP)
	mux.HandleFunc("/get_kp", s.getKP)
	mux.HandleFunc("/subscribe", s.handleSubscribe)
	mux.HandleFunc("/unsubscribe", s.handleUnsubscribe)

	go s.startKeyRotationLoop()

	return http.ListenAndServe(port, mux)
}
