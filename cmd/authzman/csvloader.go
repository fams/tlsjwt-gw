package authzman

import (
	"bufio"
	"encoding/csv"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// CsvDB - Estrutura que armazena as configuracoes para acesso ao provedor
type CsvDB struct {
	CsvPath string
}

// LoadPermissions - carrega as permissões de um arquivo CVS no formato:
// fingerprint,path,claim1|claim2|claim3|claim4|...
func (c *CsvDB) LoadPermissions() (PermissionMap, bool) {
	// Abre o arquivo CSV
	// INFO Onde o arquivo eh fechado?
	// Poderia utilizar um defer os.close para fechar o arquivo ao sair da
	// funcao
	csvFile, err := os.Open(c.CsvPath)
	if err != nil {
		log.Errorf("csv: erro ao carregar arquivo de permissoes: %s, error: %s", c.CsvPath, err)
		return nil, false
	}

	// Le o arquivo utilizando bibliotecas externas
	reader := csv.NewReader(bufio.NewReader(csvFile))

	// Instancia uma nova estrutura do tipo PermissionMap
	pc := PermissionMap{}

	// Le enquanto nao chegar no EOF
	for {
		// Le uma linha
		line, err := reader.Read()

		// Verifica se eh o EOF
		if err == io.EOF {
			// Sai do For
			break

			// Verifica se eh um erro != nil, ou seja != 0
		} else if err != nil {
			log.Errorf("Erro lendo credenciais: %s, error: %s", c.CsvPath, err)
			return nil, false
		}
		log.Debugf("lido Fingerprint %s, ScopeStorageEntry: %s, Claim: %s", line[0], line[1], line[2])

		// Inicia-se a construcao do array de permissoes

		// Separa todos os Claims
		permlist := strings.Split(line[2], "|")

		// Salva as informacoes lidas do CSV junto com os claims separados na
		// estrutura pc
		pc[PermissionClaim{line[0], line[1]}] = Credential{line[1], permlist}
		//		pc[PermissionClaim{permSE.Fingerprint, permSE.Credentials[i].Scope}] = Credential{permSE.Credentials[i].Permissions}

	}

	// Retorna a estrutura pc e a confirmacao de sucesso
	log.Info("filtros carregados do CSV")
	return pc, true
}
