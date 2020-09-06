package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
)

type State int
type StateFunc func() (State, error)

const (
	UnknownState State = -255
	WaitState    State = -254
	CloseState   State = -253
)

var (
	ErrUnrecognizedState = errors.New("unrecognized state")
)

type FSM struct {
	ch         chan State
	funcs      map[State]StateFunc
	initState  State
	closeState State
}

func NewFSM(funcs map[State]StateFunc, initState, closeState State) *FSM {
	return &FSM{
		ch:         make(chan State),
		funcs:      funcs,
		initState:  initState,
		closeState: closeState,
	}
}

func (f *FSM) SignalHandling(signals ...os.Signal) {
	signalCh := make(chan os.Signal)
	signal.Notify(signalCh, signals...)

	go func() {
		for sig := range signalCh {
			for _, v := range signals {
				if v == sig {
					f.nextState(f.closeState)
					return
				}
			}
		}
	}()
}

func (f *FSM) Loop() error {
	go func() {
		f.nextState(f.initState)
	}()

	for {
		s, open := <-f.ch
		if !open {
			return nil
		}

		var fn StateFunc
		if v, ok := f.funcs[s]; ok {
			fn = v
		} else {
			return ErrUnrecognizedState
		}

		go func() {
			if nxt, err := fn(); err != nil {
				fmt.Fprintf(os.Stderr, "%+v\n", err)
				f.nextState(f.closeState)
			} else if nxt == CloseState {
				close(f.ch)
			} else if nxt > 0 {
				f.nextState(nxt)
			}
		}()
	}
}

func (f *FSM) nextState(s State) {
	f.ch <- s
}
