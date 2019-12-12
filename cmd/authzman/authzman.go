package authzman

import "extauth/cmd/config"

// par de certificate fingerprint + path
type PermissionClaim struct {
	Fingerprint, Scope string
}

//PermissionsContainer a serem adicionadas
type PermissionsContainer struct {
	Permissions []string
}

type PermissionMap map[PermissionClaim]PermissionsContainer

type AuthzDB interface {
	Validate(pc PermissionClaim) (PermissionsContainer, bool)
	Async()(bool)
}


func NewPermDb(config config.DBConf) (AuthzDB){
	//var options  map[string]string
	options := config.Options
	switch config.DBType {
		case "s3":
			permdb := S3DB{options["BucketName"],options["key"], options["region"]}
			return NewAsyncStorage(&permdb)

	case "csv":
			permdb := CsvDB{options["csvpath"]}
			return NewAsyncStorage(&permdb)
	}
	return nil
}

