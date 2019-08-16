package jwthandler

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lestrrat-go/jwx"
	"github.com/fams/jwt-go"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
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

// getIssuerCerts Recupera os JWKs por issuer e retorna o
func getJwksfromUrl(url string) (*Jwks, error) {

	resp, err := http.Get(fmt.Sprintf(url))

	if err != nil {
		return &Jwks{}, err
	}
	defer resp.Body.Close()

	var jwks = &Jwks{}
	err = json.NewDecoder(resp.Body).Decode(jwks)

	if err != nil {
		return &Jwks{}, err
	}
	return jwks, nil
}

// getIssuerCerts Recupera os JWKs por issuer e retorna o
func getJwksfromFile(path string) (*Jwks, error) {

	fileReader, err := os.Open(path)

	if err != nil {
		return &Jwks{}, err
	}

	var jwks = &Jwks{}
	err = json.NewDecoder(fileReader).Decode(jwks)

	if err != nil {
		return &Jwks{}, err
	}
	return jwks, nil
}

func (j *JwtHandler) AddJWKS(issuer string, kind string, src string) (e error) {
	//var getJwks func(string) (*Jwks, error)
	var (
		jwks *Jwks
		err  error
	)

	switch kind {
	case "local":
		jwks, err = getJwksfromFile(src)
	case "remote":
		jwks, err = getJwksfromUrl(src)
	}
	//jwks, err := getJwks(src)
	if err != nil {
		return err
	}

	j.AuthorizedIssuers[issuer] = jwks

	return nil

}

// Options is a struct for specifying configuration options for the middleware.

type Options struct {
	AuthorizedIssuers []string
}


//FIXME
// ValidateJWt tem de receber um token  validar contra algum dos issuers cadastrados

func (j *JwtHandler) ValidateJwt(tokenString string) (bool, error) {


	// Now parse the token
	var parsedToken *jwt.Token
	var err error
	for issuer, jwks := range j.AuthorizedIssuers {
		log.Debugf("Check issuer: %s",issuer)
		parsedToken, err = jwt.Parse(tokenString, func(token *jwt.Token) (***REMOVED***face{}, error) {
			checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(issuer, false)
			if !checkIss {
				return nil, errors.New("Invalid issuer.")
			}
			var cert string
			for k, _ := range jwks.Keys {
				log.Debugf("token.headers %s jwk.kid: %s",token.Header["kid"],jwks.Keys[k].Kid )
				if token.Header["kid"] == nil {
					cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].n + "\n-----END CERTIFICATE-----"
				}
				if token.Header["kid"] == jwks.Keys[k].Kid {
					cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
				}
			}

			if cert == "" {
				err := errors.New("Unable to find appropriate key.")
				return nil, err
			}

			result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			return result, nil
		})
		if err == nil {
			break
		}
	}


	// Check if there was an error in parsing...
	if err != nil {
		return false, fmt.Errorf("Error parsing token: %v", err)
	}

	if jwt.SigningMethodRS256 != parsedToken.Header["alg"] {
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