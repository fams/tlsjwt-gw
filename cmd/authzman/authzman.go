package authzman

import (
	"extauth/cmd/config"
	"time"
)

// Container para as permissoes
type PermissionStorageEntry struct {
	Fingerprint, Name string
	Credentials       []Credential
}

// par de certificate fingerprint + path
type PermissionClaim struct {
	Fingerprint, Scope string
}

//Credential a serem adicionadas
type Credential struct {
	Scope       string   `json:"scope" bson:"scope"`
	Permissions []string `json:"permissions,omitempty" bson:"permissions,omitempty"`
}

type PermissionMap map[PermissionClaim]Credential

type AuthzDB interface {
	Validate(pc PermissionClaim) (Credential, bool)
	Async() bool
	Init(tick *time.Ticker)
}

func NewPermDb(config config.DBConf) AuthzDB {

	options := config.Options
	switch config.DBType {
	case "s3":
		permdb := S3DB{options["BucketName"], options["key"], options["region"]}
		return NewAsyncStorage(&permdb)

	case "csv":
		permdb := CsvDB{options["CsvPath"]}
		return NewAsyncStorage(&permdb)

	case "mongo":
		return NewMongoStorage(config)
	}
	return nil
}
