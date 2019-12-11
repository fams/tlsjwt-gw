package credential

import (
	"testing"
	//"time"
)

func TestCredential(t *testing.T) {
	bucket := "resultfams"
	key := "credentials.json"
	region := "us-east-1"

	loader := S3loader{bucket, key, region}
	//Carregando permissões iniciais
	credentialMap := New(&loader)
	fingerprint := "fingerprint1"
	claims, okValidate := credentialMap.Validate(Principal{fingerprint, "f1scope"})
	if !okValidate {
		t.Errorf("Validação de fingerprint %s", fingerprint)
	}

	claim := "param-get"
	if claims.Permission[0] != claim {
		t.Errorf("Claim  %s "+
			"nao encontrado", claim)
	}

}
