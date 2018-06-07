package jwt

import (
	"fmt"
	"os"
	"strings"

	"github.com/antoniomo/jose-tool/util"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/spf13/cobra"

	sjwk "github.com/lestrrat-go/jwx/jwk"
	sjwt "github.com/lestrrat-go/jwx/jwt"
)

// Sign ...
var sign = &cobra.Command{
	Use:   "sign [options]",
	Short: "sign JWT payload",
	Run:   signRun,
}

func signRun(cmd *cobra.Command, args []string) {
	if opt.key == "" {
		fmt.Println("error: expecting a key filename or string")
		cmd.Help()
		os.Exit(1)
	}

	// Normalize
	opt.algorithm = strings.ToUpper(opt.algorithm)

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
		priv, isSet = util.LoadPrivateKey(k)
	}
	cl := util.ReadInput(opt.claims)
	tok := sjwt.New()
	err = tok.UnmarshalJSON(cl)
	util.ExitOnError("unable to parse claims", err)

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

	payload, err := tok.Sign(a, priv)
	util.ExitOnError("signing failure", err)

	util.WriteOutput(opt.output, payload)
}

func init() {
	sign.Flags().StringVarP(&opt.output, "output", "o", "", "output file")
	sign.Flags().StringVarP(&opt.algorithm, "alg", "a", "RS256", "signature algorithm")
	sign.Flags().StringVarP(&opt.key, "key", "k", "", "private key (filename or string for HSXXX alg)")
	sign.Flags().StringVarP(&opt.kid, "kid", "", "", "private key id (for jwks)")
	sign.Flags().StringVarP(&opt.claims, "claims", "c", "", "claims json file")

	JWT.AddCommand(sign)
}
