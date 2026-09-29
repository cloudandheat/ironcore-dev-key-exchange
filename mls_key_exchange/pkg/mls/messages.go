// Wire protocol between agent and server. The server keeps its own copy of these definitions,
// both have to match.
package mls

// must match the server
const (
	bootIDHeader = "X-Mls-Server-Boot-Id"

	msgOp           = "op"
	msgCommit       = "commit"
	msgWelcome      = "welcome"
	msgRoundPrepare = "round_prepare"
	msgRoundInstall = "round_install"
	msgRoundSwitch  = "round_switch"
	msgRoundCleanup = "round_cleanup"
	msgPeerLeft     = "peer_left"

	opAdd    = "add"
	opReadd  = "readd"
	opRemove = "remove"
	opUpdate = "update"

	secretLabel = "default-app-secret"
)

type Envelope struct {
	Type  string `json:"Type"`
	From  string `json:"From"`
	Epoch uint64 `json:"Epoch"`
	VNI   uint32 `json:"VNI"`
	Data  []byte `json:"Data"`
}

type WelcomePayload struct {
	Welcome []byte `json:"welcome"`
	Tree    []byte `json:"tree"`
}

type Op struct {
	ID   uint64 `json:"id"`
	Kind string `json:"kind"`
	User string `json:"user"`
}

type OpResult struct {
	ID      uint64   `json:"id"`
	Failed  bool     `json:"failed"`
	Epoch   uint64   `json:"epoch"`
	Members []string `json:"members"`
}

type RoundPeer struct {
	User string `json:"user"`
	IP   string `json:"ip"`
	Slot int    `json:"slot"`
}

type RoundMsg struct {
	Epoch uint64      `json:"epoch"`
	Peers []RoundPeer `json:"peers,omitempty"`
}

type PeerLeftMsg struct {
	User string `json:"user"`
	IP   string `json:"ip"`
}
