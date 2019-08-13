package main

import "testing"

func TestFingerprint(t *testing.T) {
	fg, err := FromFingerprintHeader("Hash=2bfb74b109f3bf08a4f806878c569131315ccc2cc583e995b552b0fd61bff87e")
	if  err != nil{
		t.Errorf("Nao extraido fingerprint, erro: %v",err)
	}
	if len(fg) < 1 {
		t.Errorf("Nao extraido fingerprint, recebido %s", fg)
	}
}
