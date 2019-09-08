package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/f110/lagrangian-proxy/pkg/config"
	"github.com/f110/lagrangian-proxy/pkg/frontproxy"
	"github.com/spf13/pflag"
)

type mainProcess struct {
	Stop context.CancelFunc

	ctx   context.Context
	wg    sync.WaitGroup
	conf  *config.Config
	front *frontproxy.FrontendProxy
}

func newMainProcess() *mainProcess {
	ctx, cancelFunc := context.WithCancel(context.Background())
	m := &mainProcess{Stop: cancelFunc, ctx: ctx}

	m.signalHandling()
	return m
}

func (m *mainProcess) readConfig(p string) error {
	f, err := os.Open(p)
	if err != nil {
		return err
	}

	conf, err := config.ReadConfig(f)
	if err != nil {
		return err
	}
	m.conf = conf

	return nil
}

func (m *mainProcess) shutdown(ctx context.Context) {
	if m.front != nil {
		if err := m.front.Shutdown(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "%+v", err)
		}
	}
}

func (m *mainProcess) signalHandling() {
	signalCh := make(chan os.Signal)
	signal.Notify(signalCh, syscall.SIGTERM)

	go func() {
		for sig := range signalCh {
			switch sig {
			case syscall.SIGTERM:
				m.Stop()
				ctx, cancelFunc := context.WithTimeout(m.ctx, 30*time.Second)
				m.shutdown(ctx)
				cancelFunc()
				return
			}
		}
	}()
}

func (m *mainProcess) startFrontendProxy() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()

		m.front = frontproxy.NewFrontendProxy()
		if err := m.front.Serve(); err != nil {
			fmt.Fprintln(os.Stderr, "%+v", err)
		}
	}()
}

func (m *mainProcess) Wait() {
	m.Wait()
}

func command(args []string) error {
	confFile := ""
	fs := pflag.NewFlagSet("lagrangian-proxy", pflag.ContinueOnError)
	fs.StringVarP(&confFile, "config", "c", confFile, "Config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	mainProcess := newMainProcess()
	if err := mainProcess.readConfig(confFile); err != nil {
		return err
	}

	mainProcess.Wait()
	return nil
}

func main() {
	if err := command(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "%+v", err)
		os.Exit(1)
	}
}
