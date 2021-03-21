package etcd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/gob"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/v3/clientv3"
	"go.etcd.io/etcd/v3/etcdserver/etcdserverpb"
	"go.etcd.io/etcd/v3/mvcc/mvccpb"

	"go.f110.dev/heimdallr/pkg/cert"
	"go.f110.dev/heimdallr/pkg/database"
)

func newCertificate(t *testing.T) *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	serial, err := cert.NewSerialNumber()
	require.NoError(t, err)
	v := &x509.Certificate{SerialNumber: serial}
	newCertBuf, err := x509.CreateCertificate(rand.Reader, v, v, privateKey.Public(), privateKey)
	require.NoError(t, err)

	newCert, err := x509.ParseCertificate(newCertBuf)
	require.NoError(t, err)

	return newCert
}

func TestNewCA(t *testing.T) {
	ca := NewCA(client)
	defer ca.Close()
	assert.NotNil(t, ca)
}

func TestCA(t *testing.T) {
	ca := NewCA(client)
	defer ca.Close()

	err := ca.SetSignedCertificate(context.Background(), &database.SignedCertificate{
		Certificate: newCertificate(t),
		IssuedAt:    time.Now(),
		Comment:     "test",
	})
	require.NoError(t, err)
	err = ca.SetSignedCertificate(context.Background(), &database.SignedCertificate{
		Certificate: newCertificate(t),
		IssuedAt:    time.Now(),
		Comment:     "test 2",
	})
	require.NoError(t, err)
	certs, err := ca.GetSignedCertificate(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, certs, 2)
	firstCert, err := ca.GetSignedCertificate(context.Background(), certs[0].Certificate.SerialNumber)
	require.NoError(t, err)
	require.Len(t, firstCert, 1)
	assert.Equal(t, certs[0].Certificate.SerialNumber, firstCert[0].Certificate.SerialNumber)

	err = ca.SetRevokedCertificate(context.Background(), &database.RevokedCertificate{
		SerialNumber: certs[0].Certificate.SerialNumber,
	})
	require.NoError(t, err)
	revokes, err := ca.GetRevokedCertificate(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, revokes, 1)
}

func TestCA_NewSerialNumber(t *testing.T) {
	ca := NewCA(client)
	defer ca.Close()

	serial, err := ca.NewSerialNumber(context.Background())
	require.NoError(t, err)
	newSerial, err := ca.NewSerialNumber(context.Background())
	require.NoError(t, err)
	assert.NotEqual(t, serial, newSerial)
}

func TestCA_Watch(t *testing.T) {
	t.Run("Reconnect", func(t *testing.T) {
		mock := NewMockEtcdClient()
		c := &clientv3.Client{
			KV:      mock,
			Watcher: mock,
		}
		ca := NewCA(c)
		require.NotNil(t, ca)
		watchCh := ca.WatchRevokeCertificate()

		ch := mock.WaitWatch(time.Second)
		require.NotNil(t, ch)
		// First channel should close to testing reconnect
		close(ch)

		ch = mock.WaitWatch(time.Second)
		require.NotNil(t, ch)
		ch <- clientv3.WatchResponse{
			Events: []*clientv3.Event{
				{
					Kv: &mvccpb.KeyValue{
						Value: newRevokedCertificate(t, "reconnect"),
					},
				},
			},
		}
		select {
		case r := <-watchCh:
			assert.Equal(t, "reconnect", r.CommonName)
		case <-time.After(time.Second):
			require.Fail(t, "didn't receive the data via watch channel")
		}
		assert.Len(t, ca.revokedList, 2)
	})
}

func newRevokedCertificate(t *testing.T, commonName string) []byte {
	t.Helper()

	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(&database.RevokedCertificate{
		CommonName: commonName,
	})
	require.NoError(t, err)

	return buf.Bytes()
}

type MockEtcdClient struct {
	watchCh chan chan clientv3.WatchResponse
}

func NewMockEtcdClient() *MockEtcdClient {
	return &MockEtcdClient{
		watchCh: make(chan chan clientv3.WatchResponse, 1),
	}
}

func (m *MockEtcdClient) WaitWatch(timeout time.Duration) chan clientv3.WatchResponse {
	select {
	case <-time.After(timeout):
		return nil
	case ch := <-m.watchCh:
		return ch
	}
}

func (m *MockEtcdClient) Watch(_ context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan {
	ch := make(chan clientv3.WatchResponse)
	m.watchCh <- ch
	return ch
}

func (m *MockEtcdClient) RequestProgress(_ context.Context) error {
	panic("implement me")
}

func (m *MockEtcdClient) Close() error {
	panic("implement me")
}

func (m *MockEtcdClient) Put(_ context.Context, key, val string, opts ...clientv3.OpOption) (*clientv3.PutResponse, error) {
	panic("implement me")
}

func (m *MockEtcdClient) Get(_ context.Context, _ string, _ ...clientv3.OpOption) (*clientv3.GetResponse, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(&database.RevokedCertificate{
		CommonName: "test",
	}); err != nil {
		return nil, err
	}

	return &clientv3.GetResponse{
		Kvs: []*mvccpb.KeyValue{
			{Value: buf.Bytes()},
		},
		Header: &etcdserverpb.ResponseHeader{
			Revision: 1,
		},
	}, nil
}

func (m *MockEtcdClient) Delete(_ context.Context, key string, opts ...clientv3.OpOption) (*clientv3.DeleteResponse, error) {
	panic("implement me")
}

func (m *MockEtcdClient) Compact(_ context.Context, rev int64, opts ...clientv3.CompactOption) (*clientv3.CompactResponse, error) {
	panic("implement me")
}

func (m *MockEtcdClient) Do(_ context.Context, op clientv3.Op) (clientv3.OpResponse, error) {
	panic("implement me")
}

func (m *MockEtcdClient) Txn(_ context.Context) clientv3.Txn {
	panic("implement me")
}
