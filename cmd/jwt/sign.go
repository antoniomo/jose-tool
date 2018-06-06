package jwt

import (
	"fmt"
	"os"
	"strings"

	"github.com/antoniomo/jose-tool/util"
	"github.com/lestrrat-go/jwx/jwa"
	sjwt "github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
)

type signOptions struct {
	output    string
	algorithm string
	key       string
	claims    string
}

var so signOptions

// Sign ...
var sign = &cobra.Command{
	Use:   "sign [options]",
	Short: "sign JWT payload",
	Run:   signRun,
}

func signRun(cmd *cobra.Command, args []string) {
	if so.key == "" {
		fmt.Println("error: expecting a key filename or string")
		cmd.Help()
		os.Exit(1)
	}

	// Normalize
	so.algorithm = strings.ToUpper(so.algorithm)

	var a jwa.SignatureAlgorithm
	err := a.Accept(so.algorithm)
	util.ExitOnError("wrong signature algorithm", err)

	var priv interface{}
	if strings.HasPrefix(so.algorithm, "HS") {
		priv = []byte(so.key)
	} else {
		// If it's not HMAC type of key, grab from file
		k := util.ReadInput(so.key)
		priv = util.LoadPrivateKey(k)
	}
	cl := util.ReadInput(so.claims)
	tok := sjwt.New()
	err = tok.UnmarshalJSON(cl)
	util.ExitOnError("unable to parse claims", err)

	payload, err := tok.Sign(a, priv)
	util.ExitOnError("signing failure", err)

	util.WriteOutput(so.output, payload)
}

func init() {
	sign.Flags().StringVarP(&so.output, "output", "o", "", "output file")
	sign.Flags().StringVarP(&so.algorithm, "alg", "a", "RS256", "signature algorithm")
	sign.Flags().StringVarP(&so.key, "key", "k", "", "private key (filename or string for HSXXX alg)")
	sign.Flags().StringVarP(&so.claims, "claims", "c", "", "claims json file")

	JWT.AddCommand(sign)
}
