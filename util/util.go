package util

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	sjwk "github.com/lestrrat-go/jwx/jwk"
)

// Some generic utils
// Taken pretty much from https://github.com/square/go-jose/blob/v2/jose-util/main.go

// ExitOnError and print error message if we encountered a problem
func ExitOnError(msg string, errs ...error) {
	var exit bool
	for _, err := range errs {
		if err != nil {
			exit = true
			fmt.Fprintf(os.Stderr, "%s: %s\n", msg, err)
		}
	}
	if exit {
		os.Exit(1)
	}
}

// ReadInput from file or stdin
func ReadInput(path string) []byte {
	var bytes []byte
	var err error

	if path != "" {
		bytes, err = ioutil.ReadFile(path)
	} else {
		bytes, err = ioutil.ReadAll(os.Stdin)
	}

	ExitOnError("unable to read input", err)
	return bytes
}

// WriteOutput to file or stdin
func WriteOutput(path string, data []byte) {
	var err error

	if path != "" {
		err = ioutil.WriteFile(path, data, 0644)
	} else {
		_, err = os.Stdout.Write(data)
	}

	ExitOnError("unable to write output", err)
}

// WriteAsJSON writes the object as a JSON
func WriteAsJSON(path string, object interface{}) {
	jsonbuf, err := json.MarshalIndent(object, "", "  ")
	ExitOnError("failed to generate JSON", err)
	WriteOutput(path, jsonbuf)
}

// LoadPublicKey loads a public key from JWKs or PEM/DER data.
func LoadPublicKey(data []byte) (interface{}, bool) {
	input := data

	// Is it a jwk?
	set, err0 := sjwk.Parse(input)
	if err0 == nil {
		return set, true
	}

	// Try PEM/DER file
	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	// Try to load SubjectPublicKeyInfo
	pub, err1 := x509.ParsePKIXPublicKey(input)
	if err1 == nil {
		return pub, false
	}

	cert, err2 := x509.ParseCertificate(input)
	if err2 == nil {
		return cert.PublicKey, false
	}

	ExitOnError("failed to parse public key", err0, err1, err2)
	return nil, false
}

// LoadPrivateKey loads a private key from JWKs or PEM/DER data.
func LoadPrivateKey(data []byte) (interface{}, bool) {
	input := data

	// Is it a jwk?
	set, err0 := sjwk.Parse(input)
	if err0 == nil {
		return set, true
	}

	// Try PEM/DER file
	block, _ := pem.Decode(data)
	if block != nil {
		input = block.Bytes
	}

	var (
		priv interface{}
	)
	priv, err1 := x509.ParsePKCS1PrivateKey(input)
	if err1 == nil {
		return priv, false
	}

	priv, err2 := x509.ParsePKCS8PrivateKey(input)
	if err2 == nil {
		return priv, false
	}

	priv, err3 := x509.ParseECPrivateKey(input)
	if err3 == nil {
		return priv, false
	}

	ExitOnError("failed to parse private key", err0, err1, err2, err3)
	return nil, false
}
