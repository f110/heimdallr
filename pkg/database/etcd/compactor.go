package etcd

import (
	"context"
	"strconv"
	"time"

	"github.com/coreos/etcd/clientv3"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/f110/lagrangian-proxy/pkg/logger"
)

const (
	compactKey = "last_compact_rev"
)

var compactionInterval = 5 * time.Minute

type Compactor struct {
	client  *clientv3.Client
	rev     int64
	version int64
}

func NewCompactor(client *clientv3.Client) (*Compactor, error) {
	res, err := client.Get(context.Background(), compactKey)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	rev := int64(0)
	version := int64(0)
	if len(res.Kvs) > 0 {
		rev = res.Header.Revision
		version = res.Kvs[0].Version
	}

	return &Compactor{client: client, rev: rev, version: version}, nil
}

func (c *Compactor) Start(ctx context.Context) {
	t := time.NewTicker(compactionInterval)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if err := c.compact(); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func (c *Compactor) compact() error {
	logger.Log.Debug("Compact")
	res, err := c.client.Txn(context.Background()).If(
		clientv3.Compare(clientv3.Version(compactKey), "=", c.version),
	).Then(
		clientv3.OpPut(compactKey, strconv.FormatInt(c.rev, 10)),
	).Else(
		clientv3.OpGet(compactKey),
	).Commit()
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	currentRev := res.Header.Revision
	if !res.Succeeded {
		c.version = res.Responses[0].GetResponseRange().Kvs[0].Version
		c.rev = currentRev
		return nil
	}

	if c.rev == currentRev {
		return nil
	}

	if _, err := c.client.Compact(context.Background(), c.rev); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	logger.Log.Info("Finish Compaction", zap.Int64("Revision", c.rev))

	c.rev = currentRev
	c.version++
	return nil
}
