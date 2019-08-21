package jwthandler

import (
	"crypto/rsa"
	"fmt"
	"github.com/fams/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
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
	signKey           *rsa.PrivateKey
	localIssuer       string
	//AuthorizedIssuers map[string]*Jwks
	Jwks              map[string]*jwk.Set
	tokenLifetime     time.Duration
	kid               string
}

//
// New recebe um []byte com a chave privada para assinar os tokens e o emissor,
// Retorna o tratador de JWT
func New(signBytes []byte, localIssuer string, tokenLifetime time.Duration, kid string) *JwtHandler {
	j := new(JwtHandler)
	var err error
	j.localIssuer = localIssuer
	j.signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	j.tokenLifetime = tokenLifetime
	j.kid	= kid
	//j.AuthorizedIssuers = make(map[string]*Jwks)
	j.Jwks = make(map[string]*jwk.Set)

	fatal(err)
	return j
}

//
// SignToken recebe uma lista de audiences a ser adicionado ao JWT e o tempo de vida do token
// Retorna um string JWS assinado com a chave privada do tratador de JWT instanciado
func (j *JwtHandler) SignToken(audiences []string, clientId string) (string, error) {
	//tokeninzador RS256

	var claims jwt.MapClaims
	// audiences tem tratamento diferente se for singular ou plural, resultando em uma string ou uma lista de strings
	if len(audiences) > 1 {

		log.Debugf("Gerando claims para %d audience", len(audiences))
		claims = jwt.MapClaims{
			"exp": time.Now().Add(time.Minute * j.tokenLifetime).Unix(),
			"iss": j.localIssuer,
			"nbf": time.Now().Unix(),
			"aud": audiences,
			"client_id": clientId,
		}

	} else {
		claims = jwt.MapClaims{
			"exp": time.Now().Add(time.Minute * j.tokenLifetime).Unix(),
			"iss": j.localIssuer,
			"nbf": time.Now().Unix(),
			"aud": audiences[0],
			"client_id": clientId,
		}
	}
	// FIXME Assinatura do token, RS256 é HardCoded
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	//Fixme HACK de kid
	token.Header["kid"] = j.kid
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(j.signKey)

	return tokenString, err
}

func (j *JwtHandler) GetConf() string {
	return fmt.Sprintf("Local Issuer: %s\n privKey: %v", j.localIssuer, j.signKey)
}
