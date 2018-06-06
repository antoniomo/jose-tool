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

var (
	n             int
	kty           string
	signing       string
	kidFormat     string
	publicOutput  string
	privateOutput string
)

// Generate ...
var generate = &cobra.Command{
	Use:   "generate [options]",
	Short: "generate jwk set",
	Args:  cobra.NoArgs,
	Run:   generateRun,
}

func generateRun(cmd *cobra.Command, args []string) {
	if n < 1 {
		fmt.Println("error: n must be at least 1")
		return
	}

	// Normalize
	kty = strings.ToUpper(kty)
	signing = strings.ToUpper(signing)

	var (
		privateSet sjwk.Set
		publicSet  sjwk.Set
		dateSep    string
	)
	if kidFormat != "" {
		dateSep = time.Now().UTC().Format("2006-01-02") + ":"
	}

	switch kty {
	case "RSA":
		var (
			kid string
		)
		for i := 0; i < n; i++ {
			rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
			util.ExitOnError("failed generate private key", err)

			if kidFormat != "" {
				kid = dateSep + strconv.Itoa(i)
			}
			privateKey, err := sjwk.New(rsakey)
			util.ExitOnError("failed to creakte JWK", err)

			if signing != "" {
				privateKey.Set("use", "sig")
				privateKey.Set("alg", signing)
			}
			if kidFormat != "" {
				privateKey.Set("kid", kid)
			}
			privateKey.Set("kid", kid)
			privateSet.Keys = append(privateSet.Keys, privateKey)

			publicKey, err := sjwk.New(&rsakey.PublicKey)
			util.ExitOnError("failed to creakte JWK", err)

			if signing != "" {
				publicKey.Set("use", "sig")
				publicKey.Set("alg", signing)
			}
			if kidFormat != "" {
				publicKey.Set("kid", kid)
			}
			publicSet.Keys = append(publicSet.Keys, publicKey)
		}
	default:
		fmt.Printf("unsupported kty: %q\n", kty)
		return
	}

	if privateOutput == "" {
		fmt.Println("---- Begin private keys ----")
	}
	util.WriteAsJSON(privateOutput, privateSet)
	if privateOutput == "" {
		fmt.Println("\n---- End private keys ----")
	}

	if publicOutput == "" {
		fmt.Println("---- Begin public keys ----")
	}
	util.WriteAsJSON(publicOutput, publicSet)
	if publicOutput == "" {
		fmt.Println("\n---- End public keys ----")
	}
}

func init() {
	generate.Flags().IntVarP(&n, "jwks", "n", 1, "# of JWK to generate in set")
	generate.Flags().StringVarP(&kty, "kty", "t", "RSA", "kty (RSA)")
	generate.Flags().StringVarP(&signing, "sign", "s", "RS256", "signing method [RS256|RS384|RS512]")
	generate.Flags().StringVarP(&kidFormat, "kidf", "i", "date:sequence", "kid format [date:sequence]")
	generate.Flags().StringVarP(&publicOutput, "public-output", "o", "", "public keys output file")
	generate.Flags().StringVarP(&privateOutput, "private-output", "p", "", "private keys output file")

	JWK.AddCommand(generate)
}
