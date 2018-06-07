package jwt

import (
	"github.com/spf13/cobra"
)

type jwtOptions struct {
	input      string
	output     string
	algorithm  string
	key        string
	kid        string
	claims     string
	toDateTime bool
}

var opt jwtOptions

// JWT root subcommand
var JWT = &cobra.Command{
	Use:   "jwt [options]",
	Short: "handle JWT",
	Args:  cobra.NoArgs,
}
