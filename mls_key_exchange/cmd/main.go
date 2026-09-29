package main

import (
	"os"

	"github.com/cloudandheat/ironcore-dev-key-exchange/pkg/mls"
)

func main() {
	listen := os.Getenv("AGENT_LISTEN_ADDRESS")
	if listen == "" {
		listen = "[::]:50052"
	}

	agent := mls.NewAgent()
	agent.Start(listen)
}
