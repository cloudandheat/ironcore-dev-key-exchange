package main

import (
	"github.com/cloudandheat/ironcore-dev-key-exchange/pkg/mls"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.Infof("----------------- main")

	// Initializes and starts the gRPC server defined in mls.go
	agent := mls.NewAgent()
	agent.Start("[::]:50052")
}
