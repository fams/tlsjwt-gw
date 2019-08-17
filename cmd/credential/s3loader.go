package credential

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

type S3loader struct {
	BucketName string
	KeyName    string
	Region     string
}

type Scope struct {
	Name      string
	Audiences []string
}
type Credential struct {
	Fingerprint, Name string
	Scopes            []Scope
}

// Carrega as permissoes de um bucket s3
func (s *S3loader) LoadCredentials() (PermissionClaims, bool) {
	//Nova Sessão com a AWS
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
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case s3.ErrCodeNoSuchKey:
				log.Error(s3.ErrCodeNoSuchKey, aerr.Error())
			default:
				log.Error(aerr.Error())
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

	pc := PermissionClaims{}
	for {
		var perm Credential
		if err := dec.Decode(&perm); err == io.EOF {
			break
		} else if err != nil {
			log.Errorf("Erorr, %s", err)
			return nil, false
		}
		for i := 0; i < len(perm.Scopes); i++ {
			log.Debugf("recebido Fingerprint %s, Scope	: %s, Claim: %s", perm.Fingerprint, perm.Scopes[i].Name, strings.Join(perm.Scopes[i].Audiences[:], "|"))
			pc[Permission{perm.Fingerprint, perm.Scopes[i].Name}] = AudienceList{perm.Scopes[i].Audiences}
		}
	}
	return pc, true
}
