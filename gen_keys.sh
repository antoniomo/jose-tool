#!/bin/sh

openssl genrsa -out rsapriv.pem 2048
openssl rsa -in rsapriv.pem -outform PEM -pubout -out rsapub.pem

openssl ecparam -name prime256v1 -genkey -noout -out ecpriv.pem
openssl ec -in ecpriv.pem -pubout -out ecpub.pem
