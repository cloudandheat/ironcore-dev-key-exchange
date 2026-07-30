// Package shared provides the generic interfaces that abstract away the underlying
// key exchange and secure group messaging protocols.
package shared

type ServerPlugin interface {
	// Start mounts the HTTP endpoints and begins listening.
	Start(port string) error
}

type ClientPlugin interface {
	Init(name, brokerURL string) error

	// Subscribe registers the client to a uint32 vni (topic).
	// If groups already exist under this vni, the client will be invited.
	Subscribe(vni uint32) error

	// CreateGroup creates an MLS group and registers it under a uint32 vni.
	// The server will automatically notify the client to invite all existing subscribers.
	CreateGroup(groupName string, vni uint32) error
}
