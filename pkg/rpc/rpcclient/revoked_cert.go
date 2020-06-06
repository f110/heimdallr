package rpcclient

import (
	"context"
	"math/big"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

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

			logger.Log.Debug("Recv", zap.Error(err))
			w.err = err
			return err
		}
		if len(res.Items) == 0 {
			continue
		}
		logger.Log.Debug("Got event from rpcserver", zap.Int("length", len(res.Items)))

		c := make([]*RevokedCert, len(res.Items))
		for i, v := range res.Items {
			s := big.NewInt(0)
			s.SetBytes(v.SerialNumber)
			c[i] = &RevokedCert{SerialNumber: s}
			logger.Log.Debug("Revoke Cert", zap.Int64("serial_number", s.Int64()))
		}

		w.mu.Lock()
		w.items = append(w.items)
		w.mu.Unlock()
	}
}
