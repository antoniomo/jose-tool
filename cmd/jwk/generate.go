package jwk

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
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

	fmt.Println(opt.kids)

	// Normalize
	opt.kty = strings.ToUpper(opt.kty)
	opt.signing = strings.ToUpper(opt.signing)

	var (
		privateSet sjwk.Set
		publicSet  sjwk.Set
		dateSep    string
	)
	if opt.kidFormat == "date:sequence" {
		dateSep = time.Now().UTC().Format("2006-01-02") + ":"
	} else if opt.kidFormat == "provided" {
		if len(opt.kidFormat) != opt.n {
			fmt.Println("error: -n must be == len(--kids)")
			os.Exit(1)
		}
	}

	switch opt.kty {
	case "RSA":
		var (
			kid string
		)
		for i := 0; i < opt.n; i++ {
			rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
			util.ExitOnError("failed generate private key", err)

			if opt.kidFormat == "date:sequence" {
				kid = dateSep + strconv.Itoa(i)
			} else if opt.kidFormat == "provided" {
				kid = opt.kids[i]
			}
			privateKey, err := sjwk.New(rsakey)
			util.ExitOnError("failed to create JWK", err)

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
			util.ExitOnError("failed to create JWK", err)

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
	generate.Flags().StringVarP(&opt.kidFormat, "kidf", "k", "date:sequence", "kid format [date:sequence|provided]")
	generate.Flags().StringSliceVar(&opt.kids, "kids", nil, "kids (put at least n)")
	generate.Flags().StringVarP(&opt.publicOutput, "public-output", "o", "", "public keys output file")
	generate.Flags().StringVarP(&opt.privateOutput, "private-output", "p", "", "private keys output file")

	JWK.AddCommand(generate)
}
