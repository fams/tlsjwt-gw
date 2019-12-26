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

// JwtHandler - Estrutura que armazena as inforações do JWT Gerado
type JwtHandler struct {
	signKey     *rsa.PrivateKey
	localIssuer string
	//AuthorizedIssuers map[string]*Jwks
	Jwks          map[string]*jwk.Set
	tokenLifetime time.Duration
	kid           string
}

// New - recebe um []byte com a chave privada para assinar os tokens e o emissor,
// Retorna o tratador de JWT
func New(signBytes []byte, localIssuer string, tokenLifetime time.Duration, kid string) *JwtHandler {
	// Instancia uma nova estrutura JWT
	j := new(JwtHandler)
	var err error
	// Atribui informacoes a ela
	j.localIssuer = localIssuer
	// Cria uma nova chave para o JWT
	j.signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	j.tokenLifetime = tokenLifetime
	j.kid = kid
	//j.AuthorizedIssuers = make(map[string]*Jwks)
	// Atribui um mapa ao JWKS utilizando o jwk.set importado
	j.Jwks = make(map[string]*jwk.Set)

	// Verifica a existencia de erro
	if err != nil {
		log.Fatalf("signer: Error when reading config: %v", err)
	}

	// Retorna o novo JWT
	return j
}

//
// GetSignedToken recebe uma lista de claims a ser adicionado ao JWT e o tempo de vida do token
// Retorna um string JWS assinado com a chave privada do tratador de JWT instanciado
func (j *JwtHandler) GetSignedToken(customClaims map[string][]string, clientId string) (string, error) {
	//tokeninzador RS256

	var claims jwt.MapClaims
	// no jwt, o tratamento é diferente para singular ou plural, resultando em uma string ou uma lista de strings
	claims = jwt.MapClaims{
		"exp":       time.Now().Add(time.Minute * j.tokenLifetime).Unix(),
		"iss":       j.localIssuer,
		"nbf":       time.Now().Unix(),
		"client_id": clientId,
	}
	for claimName, claimList := range customClaims {
		if len(customClaims[claimName]) > 1 {
			log.Debugf("Gerando claims para %d %s", len(claimList), claimName)
			claims[claimName] = claimList
		} else {
			claims[claimName] = claimList[0]
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

// GetConf -
func (j *JwtHandler) GetConf() string {
	return fmt.Sprintf("Local Issuer: %s\n privKey: %v", j.localIssuer, j.signKey)
}
