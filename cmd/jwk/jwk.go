package jwk

import (
	"github.com/spf13/cobra"
)

type jwkOptions struct {
	n             int
	keyLength     int
	algorithm     string
	kidFormat     string
	publicOutput  string
	privateOutput string
	kids          []string
}

var opt jwkOptions

// JWK root subcommand
var JWK = &cobra.Command{
	Use:   "jwk [options]",
	Short: "handle JWK and JWK sets",
	Args:  cobra.NoArgs,
}
