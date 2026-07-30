package shared

type ServerPlugin interface {
	Start(port string) error
}

type ClientPlugin interface {
	Init(name, brokerURL string) error

	Subscribe(vni uint32) error

	CreateGroup(groupName string, vni uint32) error
}
