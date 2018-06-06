package jwt

import (
	"github.com/spf13/cobra"
)

// JWT root subcommand
var JWT = &cobra.Command{
	Use:   "jwt [options]",
	Short: "handle JWT",
	Args:  cobra.NoArgs,
}
