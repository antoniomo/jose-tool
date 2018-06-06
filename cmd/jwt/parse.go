package jwt

import (
	"fmt"
	"time"

	"github.com/antoniomo/jose-tool/util"
	sjwt "github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
)

type parseOptions struct {
	input      string
	output     string
	toDateTime bool
}

var po parseOptions

// Parse ...
var parse = &cobra.Command{
	Use:   "parse [options]",
	Short: "parse JWT payload (without verifying anything)",
	Args:  cobra.NoArgs,
	Run:   parseRun,
}

func parseRun(cmd *cobra.Command, args []string) {

	raw := util.ReadInput(po.input)

	tok, err := sjwt.ParseBytes(raw)
	util.ExitOnError("unable to parse", err)

	util.WriteAsJSON(po.output, tok)

	if po.toDateTime {
		fmt.Println("\n----")
		if !tok.NotBefore().IsZero() {
			fmt.Println("nbf -> ", tok.NotBefore().Format(time.RFC3339))
		}
		if !tok.IssuedAt().IsZero() {
			fmt.Println("iat -> ", tok.IssuedAt().Format(time.RFC3339))
		}
		if !tok.Expiration().IsZero() {
			fmt.Println("exp -> ", tok.Expiration().Format(time.RFC3339))
		}
	}
}

func init() {
	parse.Flags().StringVarP(&po.input, "input", "i", "", "input file")
	parse.Flags().StringVarP(&po.output, "output", "o", "", "output file")
	parse.Flags().BoolVarP(&po.toDateTime, "todt", "t", false, "convert nbf/iat/exp to RFC3339 formats (on STDOUT)")

	JWT.AddCommand(parse)
}
