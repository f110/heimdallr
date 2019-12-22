package rpcclient

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/f110/lagrangian-proxy/pkg/rpc"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type RevokedCertificateWatcher struct {
	client     rpc.CertificateAuthorityClient
	privateKey *ecdsa.PrivateKey

	mu    sync.Mutex
	items []*revokedCert
	ready bool
	err   error
}

type revokedCert struct {
	SerialNumber *big.Int
}

func NewRevokedCertificateWatcher(conn *grpc.ClientConn, privateKey *ecdsa.PrivateKey) (*RevokedCertificateWatcher, error) {
	w := &RevokedCertificateWatcher{
		client:     rpc.NewCertificateAuthorityClient(conn),
		privateKey: privateKey,
		items:      make([]*revokedCert, 0),
	}

	go func() {
		for {
			w.watch()
			time.Sleep(10 * time.Second)
		}
	}()
	return w, nil
}

func (w *RevokedCertificateWatcher) Get() []*revokedCert {
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
	claim := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.StandardClaims{
		Id:        database.SystemUser.Id,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(10 * time.Second).Unix(),
	})
	token, err := claim.SignedString(w.privateKey)
	if err != nil {
		logger.Log.Info("Failed sign jwt", zap.Error(err))
		return err
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), rpc.JwtTokenMetadataKey, token)

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
			logger.Log.Debug("Recv", zap.Error(err))
			w.err = err
			return err
		}
		if len(res.Items) == 0 {
			continue
		}
		logger.Log.Debug("Got event from rpcserver", zap.Int("length", len(res.Items)))

		c := make([]*revokedCert, len(res.Items))
		for i, v := range res.Items {
			s := big.NewInt(0)
			s.SetBytes(v.SerialNumber)
			c[i] = &revokedCert{SerialNumber: s}
			logger.Log.Debug("Revoke Cert", zap.Int64("serial_number", s.Int64()))
		}

		w.mu.Lock()
		w.items = append(w.items)
		w.mu.Unlock()
	}
}
