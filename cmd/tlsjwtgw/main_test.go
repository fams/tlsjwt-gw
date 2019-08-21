package main

import "testing"

func TestFromClientCertHeader(t *testing.T) {
	certheader := "Hash=2bfb74b109f3bf08a4f806878c569131315ccc2cc583e995b552b0fd61bff87e;Subject=\"CN=client-fams,OU=Servicos UAT,O=BancoInter,L=Belo Horizonte,ST=Minas Gerais,C=BR\""

	certParts,err := FromClientCertHeader(certheader)

	if certParts.hash != "2bfb74b109f3bf08a4f806878c569131315ccc2cc583e995b552b0fd61bff87e" || err!=nil {
		t.Errorf("Hash Extratc %s and %v", certParts.hash,err)
	}
	if certParts.subject != "\"CN=client-fams,OU=Servicos UAT,O=BancoInter,L=Belo Horizonte,ST=Minas Gerais,C=BR\"" || err!=nil {
		t.Errorf("Subject Extract %s and %v", certParts.subject,err)
	}
	if cn, err := certParts.GetCn(); cn != "client-fams" || err!=nil {
		t.Errorf("Cn Extract:%s, and %v", cn,err)
	}

}