package jwk

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

	// Normalize
	opt.algorithm = strings.ToUpper(opt.algorithm)

	var (
		privateSet sjwk.Set
		publicSet  sjwk.Set
		dateSep    string
		kid        string
		kty        string
		key        interface{}
		publickey  interface{}
	)
	if opt.kidFormat == "date:sequence" {
		dateSep = time.Now().UTC().Format("2006-01-02") + ":"
	} else if opt.kidFormat == "provided" {
		if len(opt.kids) != opt.n {
			fmt.Printf("error: -n(%d) must be == len(--kids)(%d)", opt.n, len(opt.kids))
			os.Exit(1)
		}
	}

	for i := 0; i < opt.n; i++ {
		switch opt.algorithm {
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			kty = "RSA"
			_key, err := rsa.GenerateKey(rand.Reader, opt.keyLength)
			key = _key
			publickey = &_key.PublicKey
			util.ExitOnError("failed to generate private key", err)
		case "ES256", "ES384", "ES512":
			var c elliptic.Curve
			switch opt.algorithm {
			case "ES256":
				c = elliptic.P256()
			case "ES384":
				c = elliptic.P384()
			case "ES512":
				c = elliptic.P521()
			}
			kty = "EC"
			_key, err := ecdsa.GenerateKey(c, rand.Reader)
			key = _key
			publickey = &_key.PublicKey
			util.ExitOnError("failed to generate private key", err)
		default:
			fmt.Printf("unsupported key type: %q\n", opt.algorithm)
			return
		}

		if opt.kidFormat == "date:sequence" {
			kid = dateSep + strconv.Itoa(i)
		} else if opt.kidFormat == "provided" {
			kid = opt.kids[i]
		}

		privateJWK, err := sjwk.New(key)
		util.ExitOnError("failed to create JWK", err)

		privateJWK.Set("use", "sig")
		privateJWK.Set("alg", opt.algorithm)
		privateJWK.Set("kty", kty)

		if opt.kidFormat != "" {
			privateJWK.Set("kid", kid)
		}
		privateSet.Keys = append(privateSet.Keys, privateJWK)

		publicJWK, err := sjwk.New(publickey)
		util.ExitOnError("failed to create public JWK", err)

		publicJWK.Set("use", "sig")
		publicJWK.Set("alg", opt.algorithm)
		publicJWK.Set("kty", kty)

		if opt.kidFormat != "" {
			publicJWK.Set("kid", kid)
		}
		publicSet.Keys = append(publicSet.Keys, publicJWK)
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
	generate.Flags().StringVarP(&opt.algorithm, "alg", "a", "RS256", "algorithm [RS|PS|ES|HS][256|RS384|RS512]")
	generate.Flags().IntVarP(&opt.keyLength, "klength", "", 2048, "RSA key length")
	generate.Flags().StringVarP(&opt.kidFormat, "kidf", "k", "date:sequence", "kid format [date:sequence|provided]")
	generate.Flags().StringSliceVar(&opt.kids, "kids", nil, "kids (put at least n)")
	generate.Flags().StringVarP(&opt.publicOutput, "public-output", "o", "", "public keys output file")
	generate.Flags().StringVarP(&opt.privateOutput, "private-output", "p", "", "private keys output file")

	JWK.AddCommand(generate)
}
