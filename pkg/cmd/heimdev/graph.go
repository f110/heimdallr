package heimdev

import (
	"bytes"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/fsm"
)

func graph(dir string) error {
	buf := new(bytes.Buffer)
	if err := fsm.NewDotOutput(buf, dir); err != nil {
		return xerrors.Errorf(": %w", err)
	}
	buf.WriteTo(os.Stdout)
	return nil
}

func Graph(rootCmd *cobra.Command) {
	graphCmd := &cobra.Command{
		Use:   "graph",
		Short: "Visualize finite state machine with graphviz",
		RunE: func(_ *cobra.Command, args []string) error {
			return graph(args[0])
		},
	}

	rootCmd.AddCommand(graphCmd)
}
