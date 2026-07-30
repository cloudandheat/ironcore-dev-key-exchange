package main

// #cgo LDFLAGS: -L/build/rust_mls_bridge/target/release -lrust_mls_bridge -lm -ldl -lpthread
/*
// C-Header definitions matching the Rust FFI bindings.
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint8_t* data;
    size_t len;
} FfiBuffer;

void ffi_generate_credential(const char* client_id);
char* ffi_generate_key_package(const char* client_id);
void ffi_free_string(char* s);
void openmls_free_buffer(FfiBuffer buf);
void ffi_create_group(const char* client_id, const char* group_id);
FfiBuffer ffi_invite_members(const char* client_id, const char* group_id, const char* target_kp_hex, FfiBuffer* out_commit);
void ffi_process_commit(const char* client_id, const char* group_id, const uint8_t* commit_ptr, size_t commit_len);
FfiBuffer ffi_serialize_tree(const char* group_id);
void ffi_join_group(const char* client_id, const char* group_id, const uint8_t* welcome_ptr, size_t welcome_len, const uint8_t* tree_ptr, size_t tree_len);
FfiBuffer ffi_export_shared_secret(const char* client_id, const char* group_id, const char* label);
*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
	"unsafe"

	shared "github.com/cloudandheat/ironcore-dev-key-exchange/plugins/shared"
	"github.com/sirupsen/logrus"
)

func toCString(s string) *C.char { return C.CString(s) }
func freeCString(c *C.char)      { C.free(unsafe.Pointer(c)) }

func parseFfiBuffer(buf C.FfiBuffer) []byte {
	if buf.data == nil || buf.len == 0 {
		return nil
	}
	res := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.len))
	C.openmls_free_buffer(buf)
	return res
}

// =====================================================================
// Dynamic Client Plugin Implementation
// =====================================================================

type ClientImpl struct {
	name      string
	serverURL string
}

type Envelope struct {
	Type    string
	From    string
	Epoch   uint64
	GroupID string
	Data    []byte
}

// JSON Payloads
type InvitePayload struct {
	Welcome string `json:"welcome"` // base64
	Tree    string `json:"tree"`    // base64
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

			// 1. Network completely down (Server container offline)
			if err != nil {
				time.Sleep(2 * time.Second)
				continue
			}

			// 2. Clean 20-second heartbeat (No messages, just keeping connection fresh)
			if resp.StatusCode == http.StatusNoContent {
				resp.Body.Close()
				continue // Reconnect instantly
			}

			// 3. Unexpected Server Error
			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				time.Sleep(2 * time.Second) // Prevent CPU-pegging tight loop
				continue
			}

			// 4. We received a payload! Process it.
			msgType := resp.Header.Get("X-Message-Type")
			from := resp.Header.Get("X-Message-From")
			epoch, _ := strconv.ParseUint(resp.Header.Get("X-Epoch"), 10, 64)
			groupID := resp.Header.Get("X-Group-ID")
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// Construct the envelope and push it DIRECTLY into the synchronous handler
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

	// Generate Credential
	cID := toCString(name)
	C.ffi_generate_credential(cID)

	// Generate universally accessible KeyPackage
	cKp := C.ffi_generate_key_package(cID)
	pubKey := []byte(C.GoString(cKp))
	C.ffi_free_string(cKp)
	freeCString(cID)

	// ROBUSTNESS FIX: Block and retry until the server is actually accepting HTTP traffic
	url := fmt.Sprintf("%s/upload_kp?user=%s", brokerURL, name)
	for {
		resp, err := http.Post(url, "application/octet-stream", bytes.NewBuffer(pubKey))
		if err == nil && resp.StatusCode == http.StatusOK {
			break // Broker is online and accepted the key
		}
		fmt.Print("error: ", err)
		fmt.Print("resp: ", resp)
		fmt.Printf("[%s] Waiting for broker to come online...\n", c.name)
		time.Sleep(1 * time.Second)
	}

	// Start background listener
	c.startListener()
	return nil
}

func (c *ClientImpl) Subscribe(vni uint32) error {
	url := fmt.Sprintf("%s/subscribe?user=%s&id=%d", c.serverURL, c.name, vni)
	http.Get(url)
	return nil
}

func (c *ClientImpl) CreateGroup(groupName string, vni uint32) error {
	// Generate a unique internal MLS Group ID
	groupID := strconv.FormatUint(uint64(rand.Uint32()), 10)

	cID, gID := toCString(c.name), toCString(groupID)
	C.ffi_create_group(cID, gID)
	freeCString(cID)
	freeCString(gID)

	groupMembers[groupID] = append(groupMembers[groupID], c.name)
	groupEpochs[groupID] = 1

	// Register with broker
	url := fmt.Sprintf("%s/create_group?user=%s&id=%d&name=%s&vni=%s", c.serverURL, c.name, vni, groupName, groupID)
	http.Get(url)
	return nil
}

// InviteMember is triggered dynamically via the Broker's add_request.
func (c *ClientImpl) InviteMember(groupID string, peerName string) {
	// 1. Fetch KeyPackage
	resp, _ := http.Get(fmt.Sprintf("%s/get_kp?user=%s", c.serverURL, peerName))
	peerPubKey, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	currentEpoch := groupEpochs[groupID]

	cID, gID := toCString(c.name), toCString(groupID)
	cPeerKp := toCString(string(peerPubKey))

	var commit C.FfiBuffer
	welcomeBytes := parseFfiBuffer(C.ffi_invite_members(cID, gID, cPeerKp, &commit))
	commitBytes := parseFfiBuffer(commit)
	treeBytes := parseFfiBuffer(C.ffi_serialize_tree(gID))

	freeCString(cID)
	freeCString(gID)
	freeCString(cPeerKp)

	// 2. Build JSON Invitation payload
	inv := InvitePayload{
		Welcome: base64.StdEncoding.EncodeToString(welcomeBytes),
		Tree:    base64.StdEncoding.EncodeToString(treeBytes),
		Epoch:   currentEpoch + 1,
	}
	invData, _ := json.Marshal(inv)

	// 3. Send Invitation
	sendMsg(c.serverURL, peerName, "invite_payload", c.name, currentEpoch+1, groupID, invData)

	// 4. Send Commit to existing group members
	for _, member := range groupMembers[groupID] {
		if member != c.name && member != peerName {
			sendMsg(c.serverURL, member, "commit", c.name, currentEpoch, groupID, commitBytes)
		}
	}

	groupMembers[groupID] = append(groupMembers[groupID], peerName)
	groupEpochs[groupID] = currentEpoch + 1
}

// processCommit securely advances the local epoch and extracts the new secret
func (c *ClientImpl) processCommit(groupID string, env Envelope) {
	expectedEpoch := groupEpochs[groupID]

	// Handle out-of-order delivery
	if env.Epoch > expectedEpoch {
		if commitBuffer[groupID] == nil {
			commitBuffer[groupID] = make(map[uint64]Envelope)
		}
		commitBuffer[groupID][env.Epoch] = env
		return
	}

	// Apply strict chronological commit
	if env.Epoch == expectedEpoch {
		cID, gID := toCString(c.name), toCString(groupID)
		cCommit := (*C.uint8_t)(C.CBytes(env.Data))
		C.ffi_process_commit(cID, gID, cCommit, C.size_t(len(env.Data)))
		freeCString(cID)
		freeCString(gID)
		C.free(unsafe.Pointer(cCommit))

		groupEpochs[groupID] = expectedEpoch + 1
		secret, _ := c.GetSharedSecret(groupID)

		fmt.Printf("[%s] Tree Updated (Epoch %d). GroupKey Preview: %x\n", c.name, expectedEpoch+1, secret[:4])

		msgData, _ := json.Marshal(AppMessage{
			Action:        "Epoch updated successfully",
			GroupID:       groupID,
			SecretPreview: hex.EncodeToString(secret[:4]),
		})
		sendMsg(c.serverURL, env.From, "app_message", c.name, expectedEpoch+1, groupID, msgData)

		// Recursively clear buffer if future commits are waiting
		if bufEnv, ok := commitBuffer[groupID][groupEpochs[groupID]]; ok {
			delete(commitBuffer[groupID], groupEpochs[groupID])
			c.processCommit(groupID, bufEnv)
		}
	}
}

func (c *ClientImpl) GetSharedSecret(groupID string) ([]byte, error) {
	cID := toCString(c.name)
	gID := toCString(groupID)
	cLabel := toCString("default-app-secret")
	secret := parseFfiBuffer(C.ffi_export_shared_secret(cID, gID, cLabel))
	freeCString(cID)
	freeCString(gID)
	freeCString(cLabel)
	return secret, nil
}

// handleEvent processes a single message completely and synchronously.
// The network listener will not fetch the next message until this function returns.
func (c *ClientImpl) handleEvent(env Envelope) {
	logrus.WithFields(nil).Info("+++++++++++++++++++++++++++++++++++++++ handle type: ", env.Type)

	switch env.Type {

	case "add_request":
		logrus.WithFields(nil).Info("+++++++++++++++++++++++++++++++++++++++ add_request")
		// Server instructs this client (as Initiator) to add a new subscriber
		var req map[string]string
		json.Unmarshal(env.Data, &req)
		fmt.Printf("[%s] Orchestrator mandated invite of %s to Group %s\n", c.name, req["user"], req["group_id"])
		c.InviteMember(req["group_id"], req["user"])

	case "invite_payload":
		logrus.WithFields(nil).Info("+++++++++++++++++++++++++++++++++++++++ invite_payload")
		// New user receives welcome + tree
		var inv InvitePayload
		json.Unmarshal(env.Data, &inv)

		wBytes, _ := base64.StdEncoding.DecodeString(inv.Welcome)
		tBytes, _ := base64.StdEncoding.DecodeString(inv.Tree)

		cID, gID := toCString(c.name), toCString(env.GroupID)
		cWelcome := (*C.uint8_t)(C.CBytes(wBytes))
		cTree := (*C.uint8_t)(C.CBytes(tBytes))

		C.ffi_join_group(cID, gID, cWelcome, C.size_t(len(wBytes)), cTree, C.size_t(len(tBytes)))

		freeCString(cID)
		freeCString(gID)
		C.free(unsafe.Pointer(cWelcome))
		C.free(unsafe.Pointer(cTree))

		groupEpochs[env.GroupID] = inv.Epoch
		secret, _ := c.GetSharedSecret(env.GroupID)

		fmt.Printf("[%s] Joined Group %s! GroupKey Preview: %x\n", c.name, env.GroupID, secret[:4])

		// Send JSON formatted message back to initiator over MLS.
		msgData, _ := json.Marshal(AppMessage{
			Action: "Joined successfully", GroupID: env.GroupID, SecretPreview: hex.EncodeToString(secret[:4]),
		})
		sendMsg(c.serverURL, env.From, "app_message", c.name, inv.Epoch, env.GroupID, msgData)

	case "commit":
		logrus.WithFields(nil).Info("+++++++++++++++++++++++++++++++++++++++ commit")
		// Existing members update their Epoch trees
		c.processCommit(env.GroupID, env)

	case "app_message":
		logrus.WithFields(nil).Info("+++++++++++++++++++++++++++++++++++++++ app_message")
		// Print simulated decrypted E2EE traffic
		var appMsg AppMessage
		json.Unmarshal(env.Data, &appMsg)
		fmt.Printf("[%s] (Decrypted via MLS) Message from %s: Action='%s', GroupKey Match Verification: %s\n",
			c.name, env.From, appMsg.Action, appMsg.SecretPreview)
	}
}

var Plugin shared.ClientPlugin = &ClientImpl{}
