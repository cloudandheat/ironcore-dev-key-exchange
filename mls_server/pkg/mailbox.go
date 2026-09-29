// Message transport: registration of agents, their mailboxes and key packages.
package server

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
)

// getMailbox returns the mailbox of an agent and creates it, if it does not exist yet. Must be
// called with s.mu held.
func (s *ServerImpl) getMailbox(user string) chan Envelope {
	if s.mailboxes[user] == nil {
		s.mailboxes[user] = make(chan Envelope, 1000)
	}
	return s.mailboxes[user]
}

// deliver puts a message into the mailbox of an agent, from where the agent fetches it by polling.
// Mailboxes are buffered, so it never blocks, as long as the agent is not more than 1000 messages
// behind, in which case the message is dropped. A dropped message at worst stalls a round or an
// operation, which recovers by timeout. Must be called with s.mu held.
func (s *ServerImpl) deliver(user string, env Envelope) {
	select {
	case s.getMailbox(user) <- env:
	default:
		logrus.Errorf("[MLS-Broker] Mailbox of '%s' is full, dropping %s message", user, env.Type)
	}
}

// registerHandler handles /register, which an agent calls, whenever it starts with a fresh MLS
// state. Everything queued for its old state is useless now: key packages it can not decrypt
// anymore and commits for groups it does not have anymore.
func (s *ServerImpl) registerHandler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")

	s.mu.Lock()
	s.mailboxes[user] = make(chan Envelope, 1000)
	delete(s.keyPackages, user)
	s.mu.Unlock()

	logrus.Infof("[MLS-Broker] Agent '%s' registered", user)
	w.WriteHeader(http.StatusOK)
}

// sendHandler handles /send, by which an agent sends a message, e.g. a commit or a welcome, to the
// mailbox of another agent.
func (s *ServerImpl) sendHandler(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	data, _ := io.ReadAll(r.Body)

	env := Envelope{
		Type:  r.URL.Query().Get("type"),
		From:  r.URL.Query().Get("from"),
		Epoch: queryUint64(r, "epoch"),
		VNI:   queryVNI(r, "vni"),
		Data:  data,
	}

	s.mu.Lock()
	s.deliver(to, env)
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// pollHandler handles /poll, the long-poll by which an agent fetches the next message from its
// mailbox. Without a message it returns 204 after 20 seconds.
func (s *ServerImpl) pollHandler(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")

	s.mu.Lock()
	ch := s.getMailbox(user)
	s.mu.Unlock()

	select {
	case <-r.Context().Done():
		return
	case msg := <-ch:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(msg)
	case <-time.After(20 * time.Second):
		w.WriteHeader(http.StatusNoContent)
	}
}

// uploadKP handles /upload_kp, by which an agent stores a key package, so a committer can add it to
// a group.
func (s *ServerImpl) uploadKP(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	data, _ := io.ReadAll(r.Body)

	s.mu.Lock()
	s.keyPackages[user] = append(s.keyPackages[user], data)
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// getKP handles /get_kp, by which a committer fetches a key package of an agent to add it to a
// group. Every key package is handed out only once.
func (s *ServerImpl) getKP(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.keyPackages[user]) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	data := s.keyPackages[user][0]
	s.keyPackages[user] = s.keyPackages[user][1:]

	w.Write(data)
}
