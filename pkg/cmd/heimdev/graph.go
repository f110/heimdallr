package heimdev

import (
	"bytes"
	"context"
	"os"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/fsm"
)

func graph(dir string) error {
	buf := new(bytes.Buffer)
	if err := fsm.NewDotOutput(buf, dir); err != nil {
		return err
	}
	buf.WriteTo(os.Stdout)
	return nil
}

func Graph(rootCmd *cmd.Command) {
	graphCmd := &cmd.Command{
		Use:   "graph",
		Short: "Visualize finite state machine with graphviz",
		Run: func(_ context.Context, _ *cmd.Command, args []string) error {
			return graph(args[0])
		},
	}

	rootCmd.AddCommand(graphCmd)
}
