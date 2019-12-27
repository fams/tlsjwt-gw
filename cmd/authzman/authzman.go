package authzman

import (
	"extauth/cmd/config"
	"time"
)

// PermissionStorageEntry -
// Container para as permissoes
type PermissionStorageEntry struct {
	Fingerprint, Name string
	Credentials       []Credential
}

// PermissionClaim - Par de [certificate fingerprint] + [path]
type PermissionClaim struct {
	Fingerprint, Scope string
}

// Credential - Estrutura de Credencial. Possui informacoes de Scopo e
// permissoes
type Credential struct {
	Scope       string   `json:"scope" bson:"scope"`
	Permissions []string `json:"permissions,omitempty" bson:"permissions,omitempty"`
}

// PermissionMap - Mapa com as permissoes descritas pelo Claim
type PermissionMap map[PermissionClaim]Credential

// AuthzDB - Interface para conversacao com o provedor de credencial
type AuthzDB interface {
	// TODO
	Validate(pc PermissionClaim) (Credential, bool)
	// TODO
	Async() bool
	// TODO
	Init(tick *time.Ticker)
}

// NewPermDb - Identifica qual Provedor de credencial sera usado e realiza a
// leitura do fingerprint, scope e claims do mesmo.
// Tambem adiciona os metodos de semaforo e waitgroup a estrutura
func NewPermDb(config config.DBConf) AuthzDB {

	// Captura as configuracoes de acesso ao provedor de credencial
	options := config.Options

	// De acordo com cada tipo de provedor, TODO
	switch config.DBType {
	case "s3":
		permdb := S3DB{options["BucketName"], options["key"], options["region"]}
		return NewAsyncStorage(&permdb)

	case "csv":
		// Captura o caminho do arquivo CSV salva na estrutura CSVDB
		permdb := CsvDB{options["CsvPath"]}
		return NewAsyncStorage(&permdb)

	case "mongo":
		return NewMongoStorage(config)

	case "dynamodb":
		return NewDynamoStorage(config)

	default:
		return nil
	}

}
