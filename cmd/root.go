package cmd

import (
	"github.com/antoniomo/jose-tool/cmd/jwk"
	"github.com/antoniomo/jose-tool/cmd/jwt"
	"github.com/spf13/cobra"
)

// RootCmd ...
var RootCmd = &cobra.Command{
	Use:   "jose-tool",
	Short: "jose tool",
	Long:  "Command line tool to manage JOSE stuff, including JWT, JWKs and the like",
	Run:   runHelp,
}

// runHelp ...
func runHelp(cmd *cobra.Command, args []string) {
	cmd.Help()
}

func init() {
	RootCmd.AddCommand(jwk.JWK)
	RootCmd.AddCommand(jwt.JWT)
}
