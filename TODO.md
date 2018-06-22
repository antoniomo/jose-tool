# TODO

- Perhaps remove "family" verbs and use a single-level command structure?
- Examples in README
- Better help

## JWT

- On verify, show warnings if expired/not before aren't met
- No need to specify --kid if the claims have one
- Add JWK sign/verify from URL

## JWS

- Make it an alias of JWT

## JWK

- Support HS alg
- Add set handling: list kids, get/add/remove by kid...

## JWE

- Add support, similar to JWT (JWS)
