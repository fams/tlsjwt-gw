package jwthandler

import (
	"io/ioutil"
	"log"
	"testing"
	//"time"
)

func TestJwtHandler_SignToken(t *testing.T) {
	signBytes, err := ioutil.ReadFile("../../conf/extauth.rsa")
	if err != nil {
		log.Fatal(err)
	}
	myJwtHandler := New(signBytes, "local.issuer", 30, "mykid")
	var claims map[string][]string
	claims = make(map[string][]string)
	claims["aud"] = []string{"http-bin"}
	bearer, _ := myJwtHandler.GetSignedToken(claims, "fams")
	print("Token: %s", bearer)
}
