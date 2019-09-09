package main

import "testing"

func TestFromClientCertHeader(t *testing.T) {
	// Test Funcional Header
	certheader := "Hash=2bfb74b109f3bf08a4f806878c569131315ccc2cc583e995b552b0fd61bff87e;Subject=\"CN=client-fams,OU=Servicos UAT,O=BancoInter,L=Belo Horizonte,ST=Minas Gerais,C=BR\""

	certParts,err := FromClientCertHeader(certheader)

	if certParts.hash != "2bfb74b109f3bf08a4f806878c569131315ccc2cc583e995b552b0fd61bff87e" || err!=nil {
		t.Errorf("Hash Extratc %s and %v", certParts.hash, err)
	}
	if certParts.subject != "\"CN=client-fams,OU=Servicos UAT,O=BancoInter,L=Belo Horizonte,ST=Minas Gerais,C=BR\"" || err!=nil {
		t.Errorf("Subject Extract %s and %v", certParts.subject,err)
	}
	if cn, err := certParts.GetCn(); cn != "client-fams" || err!=nil {
		t.Errorf("Cn Extract:%s, and %v", cn,err)
	}
	//Fail header
	certheader = "Hash=2bfb74b109f3bf08a4f806878c569131315ccc2cc583e995b552b0fd61bff87e"
	certParts,err = FromClientCertHeader(certheader)
	if err==nil {
		t.Errorf("Error is %v, Expected not work withou Subjetct", err)
	}
	certheader = "Hash=2bfb74b109f3bf08a4f806878c569131315ccc2cc583e995b552b0fd61bff87e;Subject=\"sn=,\""
	certParts,err = FromClientCertHeader(certheader)
	if cn, cnErr := certParts.GetCn(); cnErr == nil {
		t.Errorf("Error is %v expected not work without CN, %s", err, cn)
	}
	certheader = "Has=2bfb74b109f3bf08a4f806878c569131315ccc2cc583e995b552b0fd61bff87e;subject=\"\""
	certParts,err = FromClientCertHeader(certheader)
	if err==nil {
		t.Errorf("Error is nil expected Not work without HASH in fingerprint")
	}
}