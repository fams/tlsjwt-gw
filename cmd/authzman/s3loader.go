package authzman

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	log "github.com/sirupsen/logrus"
	"io"
	"strings"
)

type S3DB struct {
	BucketName string
	KeyName    string
	Region     string
}

// Container para as permissoes, para cada
type PermissionStorageEntry struct {
	Fingerprint, Name string
	Scopes            []ScopeStorageEntry
}

type ScopeStorageEntry struct {
	Name        string
	Permissions []string
}


// Carrega as permissoes de um bucket s3
func (s *S3DB) LoadPermissions() (PermissionMap, bool) {
	//Nova Sessão com a AWS
	log.Debugf("Iniciando sessao com S3")
	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String(s.Region)},
	)
	svc := s3.New(sess)
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.BucketName),
		Key:    aws.String(s.KeyName),
	}
	//Obtem json
	result, err := svc.GetObject(input)
	if err != nil {
		if s3err, ok := err.(awserr.Error); ok {
			switch s3err.Code() {
			case s3.ErrCodeNoSuchKey:
				log.Error(s3.ErrCodeNoSuchKey, s3err.Error())
			default:
				log.Error(s3err.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			log.Error(err.Error())
		}
		// retorna vazio se não consegue
		return nil, false
	}

	dec := json.NewDecoder(result.Body)

	pc := PermissionMap{}
	for {
		var permSE PermissionStorageEntry
		//Carrega as permissoes em permSE
		if err := dec.Decode(&permSE); err == io.EOF {
			break
		} else if err != nil {
			log.Errorf("S3 Decode error, %s", err)
			return nil, false
		}
		// Para cada escopo cria uma entrada no mapa de permissoes
		for i := 0; i < len(permSE.Scopes); i++ {
			log.Debugf("recebido Fingerprint %s, ScopeStorageEntry	: %s, Claim: %s", permSE.Fingerprint, permSE.Scopes[i].Name, strings.Join(permSE.Scopes[i].Permissions[:], "|"))
			pc[PermissionClaim{permSE.Fingerprint, permSE.Scopes[i].Name}] = PermissionsContainer{permSE.Scopes[i].Permissions}
		}
	}
	return pc, true
}
