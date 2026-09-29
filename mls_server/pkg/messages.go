// Wire protocol between server and agents. The agent keeps its own copy of these definitions,
// both have to match.
package server

// Envelope types sent to the agents
const (
	MsgOp           = "op"            // committer: execute a membership operation
	MsgCommit       = "commit"        // member: process a commit
	MsgWelcome      = "welcome"       // new member: join the group
	MsgRoundPrepare = "round_prepare" // member: report own egress slots
	MsgRoundInstall = "round_install" // member: install new ingress SAs
	MsgRoundSwitch  = "round_switch"  // member: replace egress SAs
	MsgRoundCleanup = "round_cleanup" // member: delete old ingress SAs
	MsgPeerLeft     = "peer_left"     // member: delete all SAs towards a peer
)

// Membership operations
const (
	OpAdd    = "add"
	OpReadd  = "readd"
	OpRemove = "remove"
	OpUpdate = "update"
)

type Envelope struct {
	Type  string `json:"Type"`
	From  string `json:"From"`
	Epoch uint64 `json:"Epoch"`
	VNI   uint32 `json:"VNI"`
	Data  []byte `json:"Data"`
}

type Op struct {
	ID      uint64 `json:"id"`
	Kind    string `json:"kind"`
	User    string `json:"user"`
	retries int
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
	// in round_install: the slot of the egress SA the peer currently uses towards the receiver,
	// -1 if the peer has no egress SA towards the receiver
	Slot int `json:"slot"`
}

type RoundMsg struct {
	Epoch uint64      `json:"epoch"`
	Peers []RoundPeer `json:"peers,omitempty"`
}

type PeerLeftMsg struct {
	User string `json:"user"`
	IP   string `json:"ip"`
}

type BrokerResp struct {
	Status string `json:"status"`
	VNI    uint32 `json:"vni"`
}
