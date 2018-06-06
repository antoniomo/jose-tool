package jwt

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/antoniomo/jose-tool/util"
	"github.com/lestrrat-go/jwx/jwa"
	sjwt "github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
)

type verifyOptions struct {
	input      string
	output     string
	algorithm  string
	key        string
	toDateTime bool
}

var vo verifyOptions

// Verify ...
var verify = &cobra.Command{
	Use:   "verify [options]",
	Short: "verify JWS (signed JWT)",
	Args:  cobra.NoArgs,
	Run:   verifyRun,
}

func verifyRun(cmd *cobra.Command, args []string) {
	if vo.key == "" {
		fmt.Println("error: expecting a key filename or string")
		cmd.Help()
		os.Exit(1)
	}

	// Normalize
	so.algorithm = strings.ToUpper(so.algorithm)

	raw := util.ReadInput(vo.input)

	var a jwa.SignatureAlgorithm
	err := a.Accept(vo.algorithm)
	util.ExitOnError("wrong signature algorithm", err)

	var priv interface{}
	if strings.HasPrefix(vo.algorithm, "HS") {
		priv = []byte(vo.key)
	} else {
		// If it's not HMAC type of key, grab from file
		k := util.ReadInput(vo.key)
		priv = util.LoadPublicKey(k)
	}
	options := sjwt.WithVerify(a, priv)

	tok, err := sjwt.ParseBytes(raw, options)
	if err != nil {
		fmt.Printf("signature NOT OK, err: %v\n", err)
		tok, err = sjwt.ParseBytes(raw)
		util.ExitOnError("unable to parse", err)
	} else {
		fmt.Println("signature OK")
	}
	util.WriteAsJSON(vo.output, tok)

	if vo.toDateTime {
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
	verify.Flags().StringVarP(&vo.input, "input", "i", "", "input file")
	verify.Flags().StringVarP(&vo.output, "output", "o", "", "output file")
	verify.Flags().StringVarP(&vo.algorithm, "alg", "a", "RS256", "signature algorithm")
	verify.Flags().StringVarP(&vo.key, "key", "k", "", "public key (filename or string for HSXXX alg)")
	verify.Flags().BoolVarP(&vo.toDateTime, "todt", "t", true, "convert nbf/iat/exp to RFC3339 formats")

	JWT.AddCommand(verify)
}
