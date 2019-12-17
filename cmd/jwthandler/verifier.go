package jwthandler

import (
	"errors"
	"fmt"
	"github.com/fams/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	log "github.com/sirupsen/logrus"
)

type Response struct {
	Message string `json:"message"`
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// AddJWK - adiciona um JWKS para a lista de issues e chaves publicas permitidas
func (j *JwtHandler) AddJWK(issuer string, url string) error {
	// Busca os issuers na URL descrita
	set, err := jwk.Fetch(url)

	if err != nil {
		return err
	}
	// Atribui ao JWT
	j.Jwks[issuer] = set

	// Retorna sucesso
	return nil

}

//
// ValidateJWt recebe um token jwe e valida-o contra as chaves publicas dos issuers cadastrados,
// retornando true sem erros em caso de tokens permitidos e false com o erro se nao conseguir validar o token
func (j *JwtHandler) ValidateJwt(tokenString string) (bool, error) {

	// Now parse the token
	var parsedToken *jwt.Token
	var err error
	//Testa o token para cada um dos jwks
	for issuer, set := range j.Jwks {
		log.Debugf("Check issuer: %s", issuer)
		parsedToken, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
			if !checkIss {
				return nil, errors.New("invalid issuer")
			}
			// Caso o hint de certificado kid seja nulo, assume que deve usar o primeiro da lista
			if token.Header["kid"] == nil {
				keys := set.Keys[0]
				key, err := keys.Materialize()
				if err != nil {
					msg := fmt.Errorf("failed to generate public key: %s", err)
					return nil, msg
				}
				return key, err
			}
			// usa o kid para encontrar a chave a ser usada na auteticacao
			keys := set.LookupKeyID(token.Header["kid"].(string))
			if len(keys) == 0 {
				msg := fmt.Errorf("failed to lookup key: %s", err)
				return nil, msg
			}

			key, err := keys[0].Materialize()
			if err != nil {
				msg := fmt.Errorf("failed to generate public key: %s", err)
				return nil, msg
			}
			return key, nil
		})
		if err == nil {
			break
		}
	}

	// Se nao for possivel fazer o parse do token retorna falso co o erro de parse
	if err != nil {
		return false, fmt.Errorf("error parsing token: %v", err)
	}

	// FIXME Algoritmo RS256 hardcoded, futuramente podemos aceitar o ES256, mas menos que isso e negado
	if "RS256" != parsedToken.Header["alg"] {
		message := fmt.Sprintf("expected %s signing method but token specified %s",
			"RS256",
			parsedToken.Header["alg"])
		return false, fmt.Errorf("error validating token algorithm: %s", message)
	}

	// Caso o token seja de um issuer confiavel retorna ok, do contrario false com erro
	if !parsedToken.Valid {
		return false, errors.New("token is invalid")
	}
	return true, nil
}
