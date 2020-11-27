package heimctl

import (
	"crypto/tls"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/xerrors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"go.f110.dev/heimdallr/pkg/config/configutil"
	"go.f110.dev/heimdallr/pkg/rpc"
	"go.f110.dev/heimdallr/pkg/rpc/rpcclient"
)

func getClient(confFile string) (*rpcclient.Client, error) {
	conf, err := configutil.ReadConfig(confFile)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	cp := conf.CertificateAuthority.Local.CertPool
	cred := credentials.NewTLS(&tls.Config{ServerName: rpc.ServerHostname, RootCAs: cp})
	conn, err := grpc.Dial(
		conf.AccessProxy.HTTP.ServerName,
		grpc.WithTransportCredentials(cred),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: time.Second, PermitWithoutStream: true}),
	)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
	}

	c, err := rpcclient.NewWithStaticToken(conn)
	if err != nil {
		return nil, xerrors.Errorf(": %v", err)
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
		return xerrors.Errorf(": %v", err)
	}
	for _, v := range userList {
		fmt.Printf("%s\n", v.Id)
	}
	return nil
}

func Admin(rootCmd *cobra.Command) {
	confFile := ""
	role := ""

	adminCmd := &cobra.Command{
		Use:   "admin",
		Short: "Administrate the proxy",
	}

	userListCmd := &cobra.Command{
		Use: "user-list",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := getClient(confFile)
			if err != nil {
				return err
			}

			return userList(c, role)
		},
	}
	userListCmd.Flags().StringVar(&role, "role", role, "Role")
	userListCmd.Flags().StringVarP(&confFile, "config", "c", confFile, "Config file")
	adminCmd.AddCommand(userListCmd)

	rootCmd.AddCommand(adminCmd)
}
