# JWT tool

Command line tool to manage your JOSE related stuff (JWT, JWS, JWE, and JWK
sets).

I did it simply to fulfill my needs on a quick and dirty way, on top of the
awesome `https://github.com/lestrrat-go` and taking a lot of inspiration and
code from `https://github.com/square/go-jose/tree/v2/jose-util` as well, but if
there's issues or suggestions I can add functionality or polish the interface
(also check the TODO.md file).

## Installation

```
go get -d github.com/antoniomo/jose-tool
cd $GOPATH/src/github.com/antoniomo/jose-tool
dep ensure -vendor-only
go install
```

## Other similar tools

Some tools that influenced this one are:

- https://github.com/square/go-jose/tree/v2/jose-util
- https://github.com/phish108/node-jose-tools

The second one has a similar name to this one, I hope that's not a problem.
