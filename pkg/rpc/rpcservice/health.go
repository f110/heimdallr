package rpcservice

import (
	"context"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type HealthService struct{}

func NewHealthService() *HealthService {
	return &HealthService{}
}

func (h *HealthService) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}

func (h *HealthService) Watch(ctx *healthpb.HealthCheckRequest, stream healthpb.Health_WatchServer) error {
	panic("implement me")
}
