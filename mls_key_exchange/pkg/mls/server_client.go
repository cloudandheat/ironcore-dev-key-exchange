// Communication with the MLS server: requests, key packages, registration and the poll loop.
package mls

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	pb "github.com/cloudandheat/ironcore-dev-key-exchange/proto"
	"github.com/sirupsen/logrus"
)

// serverRequest sends an HTTP request to the MLS server and returns the response, which the caller
// has to close. Responses with a non-2xx status are turned into an error.
func (a *AgentImpl) serverRequest(method, path string, query url.Values, body []byte) (*http.Response, error) {
	u := fmt.Sprintf("%s%s?%s", a.serverURL, path, query.Encode())
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("%s returned %s", path, resp.Status)
	}
	return resp, nil
}

// serverPost sends a POST request to the MLS server, for calls where only success or failure
// matters.
func (a *AgentImpl) serverPost(path string, query url.Values, body []byte) error {
	resp, err := a.serverRequest(http.MethodPost, path, query, body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// sendMsg sends a message to another agent via the mailbox of the MLS server. Used by the committer
// to distribute commits and welcomes. Errors are only logged, a lost message at worst stalls an
// operation, which the server recovers from.
func (a *AgentImpl) sendMsg(to, msgType string, epoch uint64, vni uint32, data []byte) {
	err := a.serverPost("/send", url.Values{
		"to":    {to},
		"type":  {msgType},
		"from":  {a.name},
		"epoch": {strconv.FormatUint(epoch, 10)},
		"vni":   {strconv.FormatUint(uint64(vni), 10)},
	}, data)
	if err != nil {
		logrus.Errorf("[%s] Failed to send %s to %s: %v", a.name, msgType, to, err)
	}
}

// postReady tells the server, that this agent reached the given epoch of a group. As soon as all
// members did, the server starts the rekey round of the epoch.
func (a *AgentImpl) postReady(vni uint32, epoch uint64) {
	err := a.serverPost("/ready", url.Values{
		"user":  {a.name},
		"vni":   {strconv.FormatUint(uint64(vni), 10)},
		"epoch": {strconv.FormatUint(epoch, 10)},
	}, nil)
	if err != nil {
		logrus.Errorf("[%s] Failed to report epoch %d of VNI %d: %v", a.name, epoch, vni, err)
	}
}

// postRoundAck tells the server, that this agent completed a phase of the rekey round of the given
// epoch. The body carries the egress slots in the prepare phase and is empty otherwise.
func (a *AgentImpl) postRoundAck(vni uint32, epoch uint64, phase string, body []byte) {
	err := a.serverPost("/round_ack", url.Values{
		"user":  {a.name},
		"vni":   {strconv.FormatUint(uint64(vni), 10)},
		"epoch": {strconv.FormatUint(epoch, 10)},
		"phase": {phase},
	}, body)
	if err != nil {
		logrus.Errorf("[%s] Failed to ack round phase %s of VNI %d: %v", a.name, phase, vni, err)
	}
}

// generateAndUploadKP creates a new MLS key package and uploads it to the server. Committers fetch
// these key packages to add this agent to a group.
func (a *AgentImpl) generateAndUploadKP() {
	kpRes, err := a.grpcClient.GenerateKeyPackage(context.Background(), &pb.GenerateReq{ClientId: a.name})
	if err != nil {
		logrus.Errorf("[%s] Failed to generate key package: %v", a.name, err)
		return
	}

	if err := a.serverPost("/upload_kp", url.Values{"user": {a.name}}, []byte(kpRes.KeyPackageHex)); err != nil {
		logrus.Errorf("[%s] Failed to upload KeyPackage: %v", a.name, err)
	}
}

// fetchKP fetches a key package of another agent from the server, to add that agent to a group. It
// retries for up to 15 seconds, since a freshly started agent may still be uploading its key
// packages.
func (a *AgentImpl) fetchKP(user string) ([]byte, error) {
	for range 15 {
		resp, err := a.serverRequest(http.MethodGet, "/get_kp", url.Values{"user": {user}}, nil)
		if err == nil {
			kp, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				return kp, nil
			}
		}
		logrus.Warnf("[%s] KeyPackage for %s not available yet, waiting...", a.name, user)
		time.Sleep(1 * time.Second)
	}
	return nil, fmt.Errorf("no KeyPackage for %s available", user)
}

// registerLocked announces a fresh MLS state of this agent to the server, which drops everything it
// still queued for the old state, and uploads new key packages. It also stores the boot-ID of the
// server, to detect a restart of the server later. Must be called with a.mu held.
func (a *AgentImpl) registerLocked() error {
	resp, err := a.serverRequest(http.MethodPost, "/register", url.Values{"user": {a.name}}, nil)
	if err != nil {
		return err
	}
	resp.Body.Close()
	a.bootID = resp.Header.Get(bootIDHeader)

	for range 10 {
		a.generateAndUploadKP()
	}
	return nil
}

// startListener starts the poll loop, which long-polls the mailbox of this agent at the server and
// handles every received message. It also detects a restart of the server by a changed boot-ID and
// then registers and subscribes again. It is started only once, further calls do nothing.
func (a *AgentImpl) startListener() {
	if a.listening {
		return
	}
	a.listening = true

	go func() {
		for {
			a.mu.Lock()
			pollURL := fmt.Sprintf("%s/poll?user=%s", a.serverURL, url.QueryEscape(a.name))
			a.mu.Unlock()

			resp, err := a.httpClient.Get(pollURL)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}

			a.mu.Lock()
			if bootID := resp.Header.Get(bootIDHeader); bootID != "" && bootID != a.bootID {
				// The server restarted and lost all of its state. Everything is registered again,
				// while the SAs in dpservice keep the traffic running.
				logrus.Warnf("[%s] MLS server restarted (boot-id %s -> %s), registering again", a.name, a.bootID, bootID)
				resp.Body.Close()
				a.reregisterLocked()
				a.mu.Unlock()
				continue
			}
			a.mu.Unlock()

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				if resp.StatusCode != http.StatusNoContent {
					time.Sleep(2 * time.Second)
				}
				continue
			}

			var env Envelope
			err = json.NewDecoder(resp.Body).Decode(&env)
			resp.Body.Close()
			if err != nil {
				logrus.Errorf("[%s] Failed to decode poll response: %v", a.name, err)
				time.Sleep(2 * time.Second)
				continue
			}

			a.mu.Lock()
			a.handleEvent(env)
			a.mu.Unlock()
		}
	}()
}

// reregisterLocked registers at the server again and subscribes all VNIs again. Used after the
// server restarted and lost all of its state; the groups are rebuilt, while the SAs in dpservice
// keep the traffic running. Must be called with a.mu held.
func (a *AgentImpl) reregisterLocked() {
	if err := a.registerLocked(); err != nil {
		logrus.Errorf("[%s] Failed to register again: %v", a.name, err)
		a.bootID = ""
		return
	}
	for vni := range a.subscribed {
		if err := a.subscribeLocked(vni); err != nil {
			logrus.Errorf("[%s] Failed to subscribe VNI %d again: %v", a.name, vni, err)
		}
	}
}
