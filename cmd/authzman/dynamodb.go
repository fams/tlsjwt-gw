package authzman

import (
	"extauth/cmd/config"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	log "github.com/sirupsen/logrus"

	"time"
)

// DynamoCredential -
type DynamoCredential struct {
	Fingerprint string       `json:"fingerprint,omitempty" bson:"fingerprint,omitempty"`
	Name        string       `json:"name,omitempty" bson:"name,omitempty"`
	Credentials []Credential `json:"credentials,omitempty" bson:"credentials,omitempty"`
}

// DynamoDB - Estrutura con informacoes de acesso ao provedor de credenciais
type DynamoDB struct {
	region    string
	tableName string
	svc       *dynamodb.DynamoDB
}

// NewDynamoStorage -
func NewDynamoStorage(config config.DBConf) *DynamoDB {
	log.Debugf("criando objeto dynamodb com uri: %s e db: %s", config.Options["uri"], config.Options["database"])
	db := new(DynamoDB)
	db.tableName = config.Options["table"]
	db.region = config.Options["region"]

	return db
}

// LoadPermissions - Carrega as permissoes de um bucket s3
func (s *DynamoDB) LoadPermissions() (PermissionMap, bool) {

	return nil, false
}

// Validate -
func (s *DynamoDB) Validate(pc PermissionClaim) (Credential, bool) {

	log.Debugf("dynamodb: validando fingerprint %s, path: %s", pc.Fingerprint, pc.Scope)
	okClaims := false
	var claims Credential

	// Faz uma busca no DynamoDB a procura de um item que corresponda ao
	// atribudo fingerprint especificado
	result, err := s.svc.GetItem(
		&dynamodb.GetItemInput{
			TableName: aws.String(s.tableName),
			Key: map[string]*dynamodb.AttributeValue{
				"fingerprint": {
					S: aws.String(pc.Fingerprint),
				},
			},
		},
	)

	// Verifica se a busca retornou erros
	if err != nil {
		panic(fmt.Sprintf("dynamodb: falha buscar dados no dynamodb, %v", err))
		fmt.Println(err.Error())
		return claims, okClaims
	}

	// Instancia uma estrutura para o armazenamento das credenciais
	credential := DynamoCredential{}

	// Mapeia o item recuperado do dynamodb para
	err = dynamodbattribute.UnmarshalMap(result.Item, &credential)

	if err != nil {
		panic(fmt.Sprintf("dynamodb: falha ao mapear o dado recuperado no dynamoDB na aplicacao, %v", err))
		return claims, okClaims
	}

	if credential.Fingerprint == "" {
		// TODO Melhorar meus logs de saida
		fmt.Println("dynamodb: fingerprint recuperado eh vazio. Nao encontrou-se a credencial no provedor remoto dynamodb")
		return claims, okClaims
	}

	log.Debugf("dynamodb: [%d]credenciais encontradas para fingerprint %s", len(credential.Credentials), pc.Fingerprint)

	for idx := range credential.Credentials {
		log.Debugf("dynamodb: testando fingerprint %s, Scope requisitado %s, scope encontrado %s", pc.Fingerprint, pc.Scope, credential.Credentials[idx].Scope)
		if credential.Credentials[idx].Scope == pc.Scope {
			log.Debugf("dynamodb: credential %s", credential.Credentials[idx])
			okClaims = true
			claims = credential.Credentials[idx]
		}
	}
	log.Debugf("dynamodb: CredentialEntry %s", credential)

	return claims, okClaims

}

// Async -
func (s *DynamoDB) Async() bool {
	return false
}

// Init -
func (s *DynamoDB) Init(ticker *time.Ticker) {

	//Nova Sessão com a AWS
	log.Debugf("Iniciando sessao com DynamoDB")

	log.Debugf("conectando na tabela %s, do dynamodb", s.tableName)
	ticker.Stop()

	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String(s.region)},
	)
	// Cria um cliente DynamoDB
	s.svc = dynamodb.New(sess)
}
