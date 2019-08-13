package jwthandler

import (
	"crypto/rsa"
	"fmt"
	"github.com/fams/jwt-go"
	log "github.com/sirupsen/logrus"
	"time"
)

// Structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
// See examples for how to use this with your own claim types

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type JwtHandler struct {
	signKey     *rsa.PrivateKey
	localIssuer string
	AuthorizedIssuers map[string]*Jwks
}

//
// Construtor, recebe um []byte com a chave privada para assinar os tokens
func New(signBytes []byte, localIssuer string) *JwtHandler {
	j := new(JwtHandler)
	var err error
	j.localIssuer = localIssuer
	j.signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)
	return j
}

//
// SignToken gera e assina um jws baseado em uma lista de audiences
func (j *JwtHandler) SignToken(audiences []string, lifetime time.Duration) (string, error) {
	//tokeninzador RS256

	var claims jwt.MapClaims
	if len(audiences) > 1 {

		log.Debugf("Gerando claims para %d audience", len(audiences))
		claims = jwt.MapClaims{
			"exp": time.Now().Add(time.Minute * lifetime).Unix(),
			"iss": j.localIssuer,
			"nbf": time.Now().Unix(),
			"aud": audiences,
		}

	} else {
		claims = jwt.MapClaims{
			"exp": time.Now().Add(time.Minute * lifetime).Unix(),
			"iss": j.localIssuer,
			"nbf": time.Now().Unix(),
			"aud": audiences[0],
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(j.signKey)

	return tokenString, err
}

func (j *JwtHandler) GetConf() string{
	return fmt.Sprintf("Local Issuer: %s\n privKey: %v",j.localIssuer, j.signKey)
}