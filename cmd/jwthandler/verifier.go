package jwthandler

import (
	"encoding/json"
	"fmt"
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

func BuildJWKS(){

}

// Options is a struct for specifying configuration options for the middleware.

type Options struct {
	AuthorizedIssuers []string
}

// New constroi um novo JWT Handler com as opcoes passadas

//func (j *JwtHandler) New(Options Options) error {
//	for issuer, _ := range j.AuthorizedIssuers {
//
//		jwks, err := getIssuerCerts(issuer)
//
//		if err != nil {
//
//			return err
//
//		}
//		j.AuthorizedIssuers[issuer] = jwks
//	}
//	return nil
//}

//FIXME
// ValidateJWt tem de receber um token  validar contra algum dos issuers cadastrados

func (j *JwtHandler) ValidateJwt(token string) (bool, error) {
	return true, nil
}
