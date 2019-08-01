package main

import (
	"bufio"
	"encoding/csv"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
)

type CvsLoader struct {
	Cvspath string
}

func (c CvsLoader) LoadCredentials() (PermissionClaims, bool) {
	csvFile, _ := os.Open(c.Cvspath)
	reader := csv.NewReader(bufio.NewReader(csvFile))
	pc := PermissionClaims{}
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Errorf("Erro ao carregar arquivo de credenciais: %s, error: %s", c.Cvspath, err)
			return nil, false
		}
		log.Debugf("recebido Fingerprint %s, Path: %s, Claim: %s", line[0], line[1], line[2])
		pc[Permission{line[0], line[1]}] = Claims{line[2]}
	}
	log.Info("filtros carregados do CSV")
	return pc, true

}
