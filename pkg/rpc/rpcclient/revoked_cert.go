package rpcclient

import (
	"context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"go.f110.dev/heimdallr/pkg/logger"
	"go.f110.dev/heimdallr/pkg/rpc"
)

type RevokedCertificateWatcher struct {
	client rpc.CertificateAuthorityClient
	token  string

	mu    sync.Mutex
	items []*RevokedCert
	ready bool
	err   error
}

type RevokedCert struct {
	SerialNumber *big.Int
}

func NewRevokedCertificateWatcher(conn *grpc.ClientConn, token string) (*RevokedCertificateWatcher, error) {
	w := &RevokedCertificateWatcher{
		client: rpc.NewCertificateAuthorityClient(conn),
		token:  token,
		items:  make([]*RevokedCert, 0),
	}

	go func() {
		for {
			w.watch()
			time.Sleep(10 * time.Second)
		}
	}()
	return w, nil
}

func (w *RevokedCertificateWatcher) Get() []*RevokedCert {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.items
}

func (w *RevokedCertificateWatcher) IsReady() bool {
	return w.ready
}

func (w *RevokedCertificateWatcher) Error() error {
	return w.err
}

func (w *RevokedCertificateWatcher) watch() error {
	ctx := metadata.AppendToOutgoingContext(context.Background(), rpc.InternalTokenMetadataKey, w.token)

	revoked, err := w.client.GetRevokedList(ctx, &rpc.RequestGetRevokedList{})
	if err != nil {
		return err
	}
	c := make([]*RevokedCert, len(revoked.Items))
	for i, v := range revoked.Items {
		s := big.NewInt(0)
		s.SetBytes(v.SerialNumber)
		c[i] = &RevokedCert{SerialNumber: s}
	}

	w.mu.Lock()
	w.items = c
	w.mu.Unlock()

	watch, err := w.client.WatchRevokedCert(ctx, &rpc.RequestWatchRevokedCert{})
	if err != nil {
		w.err = err
		return err
	}
	defer watch.CloseSend()
	defer func() {
		w.ready = false
	}()

	w.ready = true
	for {
		res, err := watch.Recv()
		if err != nil {
			if s, ok := status.FromError(err); ok && s.Code() == codes.Canceled {
				return nil
			}

			logger.Log.Debug("Recv", slog.Any("error", err))
			w.err = err
			return err
		}
		if !res.Update {
			continue
		}
		logger.Log.Debug("Got event from rpcserver")

		revoked, err := w.client.GetRevokedList(ctx, &rpc.RequestGetRevokedList{})
		if err != nil {
			logger.Log.Warn("Could not get revoked certs", slog.Any("error", err))
			continue
		}

		c := make([]*RevokedCert, len(revoked.Items))
		for i, v := range revoked.Items {
			s := big.NewInt(0)
			s.SetBytes(v.SerialNumber)
			c[i] = &RevokedCert{SerialNumber: s}
		}

		w.mu.Lock()
		w.items = c
		w.mu.Unlock()
		logger.Log.Debug("Renew revoked items", slog.Int("Len", len(w.items)))
	}
}
