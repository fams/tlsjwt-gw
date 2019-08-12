package jwthandler

import (
	"crypto/rsa"
	"github.com/fams/jwt-go"

	log "github.com/sirupsen/logrus"
	"time"
)

// Structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
// See examples for how to use this with your own claim types

func SignToken(audiences []string, signKey *rsa.PrivateKey, lifetime time.Duration) (string, error) {
	//tokeninzador RS256

	var claims jwt.MapClaims
	if len(audiences) > 1 {

		log.Debugf("Gerando claims para %d audience", len(audiences))
		claims = jwt.MapClaims{
			"exp": time.Now().Add(time.Minute * lifetime).Unix(),
			"iss": "gwt.***REMOVED***.local",
			"nbf": time.Now().Unix(),
			"aud": audiences,
		}

	} else {
		claims = jwt.MapClaims{
			"exp": time.Now().Add(time.Minute * lifetime).Unix(),
			"iss": "gwt.***REMOVED***.local",
			"nbf": time.Now().Unix(),
			"aud": audiences[0],
		}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	//token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
	//	"audience": audience,
	//	"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	//	"nbf": time.Now().Unix(),
	//	"exp": time.Now().Add(time.Minute * lifetime).Unix(),
	//})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(signKey)

	return tokenString, err
}
