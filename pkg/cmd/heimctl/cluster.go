package heimctl

import (
	"context"
	"fmt"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

func memberList(ctx context.Context, c *rpcclient.Client) error {
	memberList, err := c.ClusterMemberList(ctx)
	if err != nil {
		return err
	}
	for i, v := range memberList {
		fmt.Printf("[%d] %s\n", i+1, v)
	}
	return nil
}

func Cluster(rootCmd *cmd.Command) {
	confFile := ""
	clusterCmd := &cmd.Command{
		Use:   "cluster",
		Short: "Administrate the proxy cluster itself",
	}
	clusterCmd.Flags().String("config", "Config file").Var(&confFile).Shorthand("c")

	memberList := &cmd.Command{
		Use: "member-list",
		Run: func(ctx context.Context, _ *cmd.Command, _ []string) error {
			c, err := getClient(ctx, confFile)
			if err != nil {
				return err
			}
			return memberList(ctx, c)
		},
	}
	clusterCmd.AddCommand(memberList)

	rootCmd.AddCommand(clusterCmd)
}
