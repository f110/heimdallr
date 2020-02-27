package lagctl

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/f110/lagrangian-proxy/pkg/config/configreader"
)

func Util(rootCmd *cobra.Command) {
	confFile := ""
	body := ""

	ghSignature := &cobra.Command{
		Use:   "github-signature",
		Short: "Generate a signature of webhook of github",
		RunE: func(_ *cobra.Command, _ []string) error {
			conf, err := configreader.ReadConfig(confFile)
			if err != nil {
				return err
			}
			h := hmac.New(sha1.New, conf.FrontendProxy.GithubWebhookSecret)
			h.Write([]byte(body))
			hash := h.Sum(nil)
			fmt.Fprintf(os.Stdout, "sha1=%s", hex.EncodeToString(hash[:]))

			return nil
		},
	}
	ghSignature.Flags().StringVarP(&confFile, "config", "c", confFile, "Config file")
	ghSignature.Flags().StringVarP(&body, "body", "d", body, "Request body")

	util := &cobra.Command{
		Use:   "util",
		Short: "Utilities",
	}
	util.AddCommand(ghSignature)

	rootCmd.AddCommand(util)
}
