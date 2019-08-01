package main

import (
	"bufio"
	"encoding/csv"
	"fmt"
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
			log.Info("Erro ao carregar arquivo de credenciais: ", c.Cvspath, " com erro", err)
			return nil, false
		}
		log.Debug(fmt.Printf("recebido Fingerprint %s, Path: %s, Claim: %s", line[0], line[1], line[2]))
		pc[Permission{line[0], line[1]}] = Claims{line[2]}
	}
	log.Print("filtros carregados do CSV")
	return pc, true

}
