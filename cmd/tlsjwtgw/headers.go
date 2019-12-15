package main

import (
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"strconv"
	"strings"
)

// FromAuthHeader is a "TokenExtractor" that takes a given Authorization Header and extracts
// the JWT token
func FromAuthHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", nil // No error, just no token
	}

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return "", errors.New("authorization header format must be Bearer {token}")
	}

	return authHeaderParts[1], nil
}

type ClientcertHeaderParts struct {
	hash    string
	subject string
}
// GetCn obtem o principal do certificado do campo cn
func (chp *ClientcertHeaderParts) GetCn() (string, error) {
	var s, _ = strconv.Unquote(chp.subject)

	parts := strings.Split(s, ",")
	if len(parts) < 1 {
		return "", fmt.Errorf("nao recebi informacao suficiente do certificado")
	}
	if strings.ToLower(parts[0][0:2]) == "cn" {
		return parts[0][3:], nil
	} else {
		return "", fmt.Errorf("string do certificado invalida:%s", s)
	}
}

// FromFingerprint extrai os dados do certificao header x-forwarded-client-cert exportado pelo mTLS

func FromClientCertHeader(ClientcertHeader string) (*ClientcertHeaderParts, error) {

	//var CertParts *ClientcertHeaderParts
	CertParts := new(ClientcertHeaderParts)

	if ClientcertHeader == "" {
		return CertParts, nil // No error, just no token
	}

	HeadersParts := strings.Split(ClientcertHeader, ";")
	if len(HeadersParts) != 2 {
		return CertParts, fmt.Errorf("certificate Information Header invalid")
	}
	log.Debugf("Certificate Header: %s, subjetct: %s", HeadersParts[0], HeadersParts[1])

	for i := 0; i < len(HeadersParts); i++ {
		if strings.ToLower(HeadersParts[i][0:4]) == "hash" {
			parts := strings.Split(HeadersParts[i], "=")
			if len(parts) < 2 {
				return CertParts, errors.New("fingerprint header format must be Hash={fingerprint}")
			} else {
				CertParts.hash = parts[1]
			}
		}
		if strings.ToLower(HeadersParts[i])[0:7] == "subject" {
			subjectString := HeadersParts[i][8:]
			CertParts.subject = subjectString
		}

	}
	if len(CertParts.hash) > 1 && len(CertParts.subject) > 1 {
		return CertParts, nil
	} else {
		return CertParts, fmt.Errorf("certificate Information Header invalid")
	}
}
