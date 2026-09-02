module github.com/cloudandheat/ironcore-dev-key-exchange

go 1.25.1

require (
	golang.org/x/net v0.53.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 // indirect
)

require (
	github.com/sirupsen/logrus v1.9.4
	google.golang.org/grpc v1.82.1
	google.golang.org/protobuf v1.36.11
)

replace github.com/ironcore-dev/dpservice/go/dpservice-go => github.com/opensovereigncloud/dpservice-ipsec-poc/go/dpservice-go v0.0.0-20260902010700-0e83ca85b5a8
