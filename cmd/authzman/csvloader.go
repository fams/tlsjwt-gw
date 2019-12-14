package authzman

import (
	"bufio"
	"encoding/csv"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"strings"
)

type CsvDB struct {
	CsvPath string
}

// LoadPermissions carrega as permissões de um arquivo CVS no formato:
// fingerprint,path,claim1|claim2
// Você pode definir varios claims separando por |
//
func (c *CsvDB) LoadPermissions() (PermissionMap, bool) {
	csvFile, err := os.Open(c.CsvPath)
	if err != nil {
		log.Errorf("csv: erro ao carregar arquivo de permissoes: %s, error: %s", c.CsvPath, err)
		return nil, false
	}
	reader := csv.NewReader(bufio.NewReader(csvFile))
	pc := PermissionMap{}
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Errorf("Erro lendo credenciais: %s, error: %s", c.CsvPath, err)
			return nil, false
		}
		log.Debugf("lido Fingerprint %s, ScopeStorageEntry: %s, Claim: %s", line[0], line[1], line[2])

		//Cosntruindo array de permissoes
		permlist := strings.Split(line[2], "|")
		pc[PermissionClaim{line[0], line[1]}] = Credential{line[1],permlist}
//		pc[PermissionClaim{permSE.Fingerprint, permSE.Credentials[i].Scope}] = Credential{permSE.Credentials[i].Permissions}

	}
	log.Info("filtros carregados do CSV")
	return pc, true
}
