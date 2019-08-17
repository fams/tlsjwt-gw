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


// AddJWK adiciona um JWKS para a lista de validos
func (j *JwtHandler) AddJWK( issuer string, url string )( error){
	set, err := jwk.Fetch(url)
	if err != nil {
		return err
	}

	j.Jwks[issuer] = set

	return nil

}
// Options is a struct for specifying configuration options for the middleware.

//type Options struct {
//	AuthorizedIssuers []string
//}


//FIXME
// ValidateJWt tem de receber um token  validar contra algum dos issuers cadastrados

func (j *JwtHandler) ValidateJwt(tokenString string) (bool, error) {


	// Now parse the token
	var parsedToken *jwt.Token
	var err error
	for issuer, set := range j.Jwks {
		log.Debugf("Check issuer: %s",issuer)
		parsedToken, err = jwt.Parse(tokenString, func(token *jwt.Token) (***REMOVED***face{}, error) {
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
			if !checkIss {
				return nil, errors.New("Invalid issuer.")
			}
			if token.Header["kid"] == nil {
				keys := set.Keys[0]
				key, err := keys.Materialize()
				if err != nil {
					msg := fmt.Errorf("failed to generate public key: %s", err)
					return nil, msg
				}
				return key, err
			}
			keys := set.LookupKeyID( token.Header["kid"].(string) )
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


	// Check if there was an error in parsing...
	if err != nil {
		return false, fmt.Errorf("Error parsing token: %v", err)
	}

	if "RS256" != parsedToken.Header["alg"] {
		message := fmt.Sprintf("Expected %s signing method but token specified %s",
			jwt.SigningMethodRS256,
			parsedToken.Header["alg"])
		return false, fmt.Errorf("Error validating token algorithm: %s", message)
	}

	// Check if the parsed token is valid...
	if !parsedToken.Valid {
		return false, errors.New("Token is invalid")
	}
	return true, nil
}