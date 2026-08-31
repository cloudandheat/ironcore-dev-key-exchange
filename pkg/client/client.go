package client

import (
	"context"
	"fmt"
	"time"

	pb "github.com/cloudandheat/ironcore-dev-key-exchange/pkg/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type AgentClient struct {
	client pb.AgentServiceClient
	conn   *grpc.ClientConn
}

func NewAgentClient(targetURL string) (*AgentClient, error) {
	conn, err := grpc.NewClient(targetURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to agent at %s: %v", targetURL, err)
	}

	return &AgentClient{
		client: pb.NewAgentServiceClient(conn),
		conn:   conn,
	}, nil
}

func (ac *AgentClient) Init(ctx context.Context, clientName, clientPrefix string) error {
	_, err := ac.client.Init(ctx, &pb.AgentInitReq{
		ClientName:   clientName,
		ClientPrefix: clientPrefix,
	})
	return err
}

func (ac *AgentClient) Subscribe(ctx context.Context, vni uint32) error {
	_, err := ac.client.Subscribe(ctx, &pb.AgentSubscribeReq{Vni: vni})
	return err
}

func (ac *AgentClient) Unsubscribe(ctx context.Context, vni uint32) error {
	_, err := ac.client.Unsubscribe(ctx, &pb.AgentUnsubscribeReq{Vni: vni})
	return err
}

func (ac *AgentClient) IsKeyReady(ctx context.Context, vni, timeout uint32) (bool, error) {
	for range timeout {
		isReadyRes, err := ac.client.IsKeyReady(ctx, &pb.AgentKeyReadyReq{Vni: vni})
		if err != nil {
			return false, err
		}

		if isReadyRes.IsReady {
			return true, nil
		}

		time.Sleep(1 * time.Second)
	}

	return false, fmt.Errorf("Timeout while requesting key")
}

func (ac *AgentClient) Close() {
	if ac.conn != nil {
		ac.conn.Close()
	}
}
