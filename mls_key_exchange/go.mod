module github.com/cloudandheat/ironcore-dev-key-exchange

go 1.25.1

require golang.org/x/sys v0.13.0 // indirect

require (
	google.golang.org/grpc v1.67.1
	google.golang.org/protobuf v1.35.1
        github.com/sirupsen/logrus v1.9.4
        github.com/ironcore-dev/dpservice/go/dpservice-go v0.3.17
)


replace github.com/ironcore-dev/dpservice/go/dpservice-go => github.com/opensovereigncloud/dpservice-ipsec-poc/go/dpservice-go main
