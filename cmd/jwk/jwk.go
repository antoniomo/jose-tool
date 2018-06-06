package jwk

import (
	"github.com/spf13/cobra"
)

// JWK root subcommand
var JWK = &cobra.Command{
	Use:   "jwk [options]",
	Short: "handle JWK and JWK sets",
	Args:  cobra.NoArgs,
}
