package credential

import (
	"bufio"
	"encoding/csv"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"strings"
)

type CsvLoader struct {
	Cvspath string
}

//CsvLoader.LoadCredentials carrega as permissões de um arquivo CVS no formato:
//fingerprint,path,claim1|claim2
//Você pode definir varios claims separando por |
//
func (c CsvLoader) LoadCredentials() (PermissionClaims, bool) {
	csvFile, err := os.Open(c.Cvspath)
	if err != nil {
		log.Errorf("Erro ao carregar arquivo de credenciais: %s, error: %s", c.Cvspath, err)
		return nil, false
	}
	defer csvFile.Close()
	reader := csv.NewReader(bufio.NewReader(csvFile))
	pc := PermissionClaims{}
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Errorf("Erro lendo credenciais: %s, error: %s", c.Cvspath, err)
			return nil, false
		}
		log.Debugf("recebido Fingerprint %s, Scope	: %s, Claim: %s", line[0], line[1], line[2])

		//Cosntruindo array de audiences
		audiences := strings.Split(line[2], "|")
		pc[Permission{line[0], line[1]}] = Claims{audiences}
	}
	log.Info("filtros carregados do CSV")
	return pc, true

}