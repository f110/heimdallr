package heimctl

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"go.f110.dev/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"go.f110.dev/heimdallr/pkg/cmd"
	"go.f110.dev/heimdallr/pkg/config/configutil"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

func getClient(confFile string) (*rpcclient.Client, error) {
	conf, err := configutil.ReadConfig(confFile)
	if err != nil {
		return nil, err
	}

	cp := conf.CertificateAuthority.CertPool
	cred := credentials.NewTLS(&tls.Config{ServerName: rpc.ServerHostname, RootCAs: cp})
	conn, err := grpc.Dial(
		conf.AccessProxy.HTTP.ServerName,
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return nil, xerrors.WithStack(err)
	}

	c, err := rpcclient.NewWithStaticToken(conn)
	if err != nil {
		return nil, err
	}

	return c, nil
}

func userList(c *rpcclient.Client, role string) error {
	var userList []*rpc.UserItem
	var err error
	if role != "" {
		userList, err = c.ListUser(role)
	} else {
		userList, err = c.ListAllUser()
	}
	if err != nil {
		return err
	}
	for _, v := range userList {
		fmt.Printf("%s\n", v.Id)
	}
	return nil
}

func Admin(rootCmd *cmd.Command) {
	confFile := ""
	role := ""

	adminCmd := &cmd.Command{
		Use:   "admin",
		Short: "Administrate the proxy",
	}

	userListCmd := &cmd.Command{
		Use: "user-list",
		Run: func(_ context.Context, _ *cmd.Command, _ []string) error {
			c, err := getClient(confFile)
			if err != nil {
				return err
			}

			return userList(c, role)
		},
	}
	userListCmd.Flags().String("role", "Role").Var(&role)
	userListCmd.Flags().String("config", "Config file").Var(&confFile).Shorthand("c")
	adminCmd.AddCommand(userListCmd)

	rootCmd.AddCommand(adminCmd)
}
