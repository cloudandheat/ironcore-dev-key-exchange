package main

import (
	server "github.com/cloudandheat/ironcore-dev-key-exchange/pkg"
)

func main() {
	var mls_server = server.NewServer()
	mls_server.Start("[::]:4713")
}
