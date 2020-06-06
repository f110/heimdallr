package lagctl

import (
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"

	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

func memberList(c *rpcclient.Client) error {
	memberList, err := c.ClusterMemberList()
	if err != nil {
		return xerrors.Errorf(": %v", err)
	}
	for i, v := range memberList {
		fmt.Printf("[%d] %s\n", i+1, v)
	}
	return nil
}

func Cluster(rootCmd *cobra.Command) {
	confFile := ""
	clusterCmd := &cobra.Command{
		Use:   "cluster",
		Short: "Administrate the proxy cluster itself",
	}
	clusterCmd.Flags().StringVarP(&confFile, "config", "c", confFile, "Config file")

	memberList := &cobra.Command{
		Use: "member-list",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := getClient(confFile)
			if err != nil {
				return err
			}
			return memberList(c)
		},
	}
	clusterCmd.AddCommand(memberList)

	rootCmd.AddCommand(clusterCmd)
}
