package lagctl

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"github.com/f110/lagrangian-proxy/pkg/rpc/rpcclient"
)

func defragment(c *rpcclient.Client) error {
	result, err := c.Defragment()
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}

	for k, v := range result {
		if v {
			fmt.Printf("%s: Success\n", k)
		} else {
			fmt.Printf("%s: Failure\n", k)
		}
	}

	return nil
}

func Internal(rootCmd *cobra.Command) {
	confFile := ""
	internalCmd := &cobra.Command{
		Use:   "internal",
		Short: "Subcommand for internal use.",
	}

	defragment := &cobra.Command{
		Use: "defragment",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := getClient(confFile)
			if err != nil {
				return err
			}
			return defragment(c)
		},
	}
	defragment.Flags().StringVarP(&confFile, "config", "c", confFile, "Config file")
	internalCmd.AddCommand(defragment)

	rootCmd.AddCommand(internalCmd)
}
