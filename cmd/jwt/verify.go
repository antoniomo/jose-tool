package jwt

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/antoniomo/jose-tool/util"
	"github.com/lestrrat-go/jwx/jwa"
	sjwk "github.com/lestrrat-go/jwx/jwk"
	sjwt "github.com/lestrrat-go/jwx/jwt"
	"github.com/spf13/cobra"
)

// Verify ...
var verify = &cobra.Command{
	Use:   "verify [options]",
	Short: "verify JWS (signed JWT)",
	Args:  cobra.NoArgs,
	Run:   verifyRun,
}

func verifyRun(cmd *cobra.Command, args []string) {
	if opt.key == "" {
		fmt.Println("error: expecting a key filename or string")
		cmd.Help()
		os.Exit(1)
	}

	// Normalize
	opt.algorithm = strings.ToUpper(opt.algorithm)

	raw := util.ReadInput(opt.input)

	var a jwa.SignatureAlgorithm
	err := a.Accept(opt.algorithm)
	util.ExitOnError("wrong signature algorithm", err)

	var (
		priv  interface{}
		isSet bool
	)
	if strings.HasPrefix(opt.algorithm, "HS") {
		priv = []byte(opt.key)
	} else {
		// If it's not HMAC type of key, grab from file
		k := util.ReadInput(opt.key)
		priv, isSet = util.LoadPublicKey(k)
	}
	// JWKs handling
	if isSet {
		set := priv.(*sjwk.Set)
		if opt.kid != "" {
			keys := set.LookupKeyID(opt.kid)
			if len(keys) == 0 {
				fmt.Printf("kid %q not found\n", opt.kid)
				os.Exit(1)
			}
			if len(keys) > 1 {
				fmt.Printf("warning: found %d keys with kid: %q, using the first one",
					len(keys), opt.kid)
			}
			priv, _ = keys[0].Materialize()
		} else {
			fmt.Printf("warning: using jwk without kid, using the first one\n")
			priv, _ = set.Keys[0].Materialize()
		}
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
	util.WriteAsJSON(opt.output, tok)

	if opt.toDateTime {
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
	verify.Flags().StringVarP(&opt.input, "input", "i", "", "input file")
	verify.Flags().StringVarP(&opt.output, "output", "o", "", "output file")
	verify.Flags().StringVarP(&opt.algorithm, "alg", "a", "RS256", "signature algorithm")
	verify.Flags().StringVarP(&opt.key, "key", "k", "", "public key (filename or string for HSXXX alg)")
	verify.Flags().StringVarP(&opt.kid, "kid", "", "", "public key id (for jwks)")
	verify.Flags().BoolVarP(&opt.toDateTime, "todt", "t", true, "convert nbf/iat/exp to RFC3339 formats")

	JWT.AddCommand(verify)
}
