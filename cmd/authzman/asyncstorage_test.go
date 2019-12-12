package authzman

import (
	"testing"
	//"time"
)

func TestCredential(t *testing.T) {
	bucket := "resultfams"
	key := "credentials.json"
	region := "us-east-1"

	loader := S3DB{bucket, key, region}
	//Carregando permissões iniciais
	credentialMap := NewAsyncStorage(&loader)
	fingerprint := "fingerprint1"
	claims, okValidate := credentialMap.Validate(PermissionClaim{fingerprint, "f1scope"})
	if !okValidate {
		t.Errorf("Validação de fingerprint %s", fingerprint)
	}

	claim := "param-get"
	if claims.Permissions[0] != claim {
		t.Errorf("Claim  %s "+
			"nao encontrado", claim)
	}

}
