package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/antoniomo/jose-tool/util"
	sjwk "github.com/lestrrat-go/jwx/jwk"
	"github.com/spf13/cobra"
)

// Generate ...
var generate = &cobra.Command{
	Use:   "generate [options]",
	Short: "generate jwk set",
	Args:  cobra.NoArgs,
	Run:   generateRun,
}

func generateRun(cmd *cobra.Command, args []string) {
	if opt.n < 1 {
		fmt.Println("error: n must be at least 1")
		return
	}

	// Normalize
	opt.kty = strings.ToUpper(opt.kty)
	opt.signing = strings.ToUpper(opt.signing)

	var (
		privateSet sjwk.Set
		publicSet  sjwk.Set
		dateSep    string
	)
	if opt.kidFormat != "" {
		dateSep = time.Now().UTC().Format("2006-01-02") + ":"
	}

	switch opt.kty {
	case "RSA":
		var (
			kid string
		)
		for i := 0; i < opt.n; i++ {
			rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
			util.ExitOnError("failed generate private key", err)

			if opt.kidFormat != "" {
				kid = dateSep + strconv.Itoa(i)
			}
			privateKey, err := sjwk.New(rsakey)
			util.ExitOnError("failed to creakte JWK", err)

			if opt.signing != "" {
				privateKey.Set("use", "sig")
				privateKey.Set("alg", opt.signing)
			}
			if opt.kidFormat != "" {
				privateKey.Set("kid", kid)
			}
			privateKey.Set("kid", kid)
			privateSet.Keys = append(privateSet.Keys, privateKey)

			publicKey, err := sjwk.New(&rsakey.PublicKey)
			util.ExitOnError("failed to creakte JWK", err)

			if opt.signing != "" {
				publicKey.Set("use", "sig")
				publicKey.Set("alg", opt.signing)
			}
			if opt.kidFormat != "" {
				publicKey.Set("kid", kid)
			}
			publicSet.Keys = append(publicSet.Keys, publicKey)
		}
	default:
		fmt.Printf("unsupported kty: %q\n", opt.kty)
		return
	}

	if opt.privateOutput == "" {
		fmt.Println("---- Begin private keys ----")
	}
	util.WriteAsJSON(opt.privateOutput, privateSet)
	if opt.privateOutput == "" {
		fmt.Println("\n---- End private keys ----")
	}

	if opt.publicOutput == "" {
		fmt.Println("---- Begin public keys ----")
	}
	util.WriteAsJSON(opt.publicOutput, publicSet)
	if opt.publicOutput == "" {
		fmt.Println("\n---- End public keys ----")
	}
}

func init() {
	generate.Flags().IntVarP(&opt.n, "jwks", "n", 1, "# of JWK to generate in set")
	generate.Flags().StringVarP(&opt.kty, "kty", "t", "RSA", "kty (RSA)")
	generate.Flags().StringVarP(&opt.signing, "sign", "s", "RS256", "signing method [RS256|RS384|RS512]")
	generate.Flags().StringVarP(&opt.kidFormat, "kidf", "i", "date:sequence", "kid format [date:sequence]")
	generate.Flags().StringVarP(&opt.publicOutput, "public-output", "o", "", "public keys output file")
	generate.Flags().StringVarP(&opt.privateOutput, "private-output", "p", "", "private keys output file")

	JWK.AddCommand(generate)
}
