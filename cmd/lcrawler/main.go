package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/f110/lagrangian-proxy/pkg/config/configreader"
	"github.com/f110/lagrangian-proxy/pkg/database"
	"github.com/f110/lagrangian-proxy/pkg/database/etcd"
	"github.com/f110/lagrangian-proxy/pkg/logger"
	"github.com/spf13/pflag"
	"golang.org/x/xerrors"
)

func command(args []string) error {
	confFile := ""
	fs := pflag.NewFlagSet("lagrangian-proxy", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	conf, err := configreader.ReadConfig(confFile)
	if err != nil {
		return err
	}
	if err := logger.Init(conf.Logger); err != nil {
		return xerrors.Errorf(": %v", err)
	}
	client, err := conf.Datastore.GetEtcdClient()
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	tokenDatabase := etcd.NewTemporaryToken(client)

	tokenCrawler := database.NewTokenCrawler(tokenDatabase)
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()

	signalCh := make(chan os.Signal)
	signal.Notify(signalCh, syscall.SIGTERM, syscall.SIGINT)
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		tokenCrawler.Crawl(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for sig := range signalCh {
			switch sig {
			case syscall.SIGTERM, os.Interrupt:
				cancelFunc()
				return
			}
		}
	}()

	wg.Wait()

	return nil
}

func main() {
	if err := command(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
