package main

import (
	"github.com/cloudandheat/ironcore-dev-key-exchange/pkg/mls"
)

func main() {
	agent := mls.NewAgent()
	agent.Start("[::]:50052")
}
