package rpcservice

import (
	"context"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

type HealthService struct {
	isReady func() bool
}

func NewHealthService(isReady func() bool) *HealthService {
	return &HealthService{isReady: isReady}
}

func (h *HealthService) Check(_ context.Context, _ *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	if h.isReady() {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	} else {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_NOT_SERVING}, nil
	}
}

func (h *HealthService) Watch(_ *healthpb.HealthCheckRequest, _ healthpb.Health_WatchServer) error {
	panic("implement me")
}
