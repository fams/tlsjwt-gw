package authzman

import (
	"extauth/cmd/config"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	log "github.com/sirupsen/logrus"

	"time"
)

var (
	// Contador de quantas credencias de sucesso foram realizadas
	totalCredenciais = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gtw_credenciais_total",
		Help: "O numero total de credenciais, tanto insucesso como sucesso",
	})
	// Contador de quantas credencias de sucesso foram realizadas
	totalCredenciaisSucesso = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gtw_credenciais_sucesso",
		Help: "O numero total de credenciais emitidas com sucesso",
	})
	// Contador de quantas credencias nao foram emitidas por algum motivo
	totalCredenciaisInsucesso = promauto.NewCounter(prometheus.CounterOpts{
		Name: "gtw_credenciais_insucesso",
		Help: "O numero total de credenciais nao emitidas, ou seja com insucesso",
	})
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
	log.Debugf("dynamodb: criando objeto dynamodb com tablename: %s e region: %s", config.Options["tableName"], config.Options["region"])
	db := new(DynamoDB)
	db.tableName = config.Options["tableName"]
	db.region = config.Options["region"]

	log.Debugf("dynamodb: informacoes de tabela '%s' e regiao '%s' salvos com sucesso", db.tableName, db.region)

	return db
}

// LoadPermissions - Carrega as permissoes de um bucket s3
func (s *DynamoDB) LoadPermissions() (PermissionMap, bool) {

	return nil, false
}

// Validate -
func (s *DynamoDB) Validate(pc PermissionClaim) (Credential, bool) {
	totalCredenciais.Inc()
	// INFO Nao esta imprimindo o pc.scope nos meus testes de dynamo
	log.Debugf("dynamodb: validando fingerprint %s, path: %s", pc.Fingerprint, pc.Scope)
	okClaims := false
	var claims Credential

	log.Debugf("dynamodb: buscando item no dynamodb")

	// Faz uma busca no DynamoDB a procura todos os scopes que aquele
	// fingerprint possui
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
		log.Infof("dynamodb: falha buscar dados no dynamodb: %v", err)
		totalCredenciaisInsucesso.Inc()
		return claims, okClaims
	}

	// Instancia uma estrutura para o armazenamento das credenciais
	credential := DynamoCredential{}

	log.Debugf("dynamodb: mapeando o item encontrado na estrutura de memoria local")
	// Mapeia o item recuperado do dynamodb para
	err = dynamodbattribute.UnmarshalMap(result.Item, &credential)

	log.Debugf("dynamodb: verificando existencia de erros no mapeamento")
	if err != nil {
		log.Infof("dynamodb: falha ao mapear o dado recuperado no dynamoDB na aplicacao, %v", err)
		totalCredenciaisInsucesso.Inc()
		return claims, okClaims
	}

	log.Debugf("dynamodb: verificando se fingerprint eh vazio")

	if credential.Fingerprint == "" {
		log.Infof("dynamodb: fingerprint recuperado eh vazio. Nao encontrou-se a credencial no provedor remoto dynamodb")
		totalCredenciaisInsucesso.Inc()
		return claims, okClaims
	}

	log.Debugf("dynamodb: [%d] credenciais encontradas para fingerprint %s", len(credential.Credentials), pc.Fingerprint)

	// Dynamodb nao aceita valores vazios, entao trocou-se todos os campos
	// vazios para '.'. Dessa forma ao procurar por:
	// - por um scope vazio '', procura-se por '.'
	// - por um scope 'escopo-a', procura-se por 'escopo-a'
	// - por um scope '.', retorna unauth pois nao aceita valores indefinidos
	// sendo '.' categorizado como indefinido.
	var escopoRequisicao string

	// Verifica se eh escopo vazio
	log.Debugf("dynamodb: checando o escopo recebido")
	if pc.Scope == "" {
		log.Debugf("dynamodb: scopo esta vazio, trocando para '.'")
		escopoRequisicao = "."
		// Verifica se o escopo possui algum nome diferente de '.'
	} else if pc.Scope != "." {
		log.Debugf("dynamodb: escopo esta preenchido, mantendo-o dessa forma")
		escopoRequisicao = pc.Scope
		// Igual a '.', entao retorna falso
	} else {
		log.Debugf("dynamodb: escopo recebido igual a '.', retornando falso")
		totalCredenciaisInsucesso.Inc()
		return claims, okClaims
	}

	log.Debugf("dynamodb: checando permissao de escopos")
	for idx := range credential.Credentials {
		log.Debugf("dynamodb: testando fingerprint %s, Scope requisitado %s, scope encontrado %s", pc.Fingerprint, pc.Scope, credential.Credentials[idx].Scope)
		if credential.Credentials[idx].Scope == escopoRequisicao {
			log.Debugf("dynamodb: credential %s", credential.Credentials[idx])
			okClaims = true
			totalCredenciaisSucesso.Inc()
			log.Debugf("dynamodb: escopo encontrado")
			claims = credential.Credentials[idx]
		}
	}

	log.Debugf("dynamodb: CredentialEntry %s", credential)
	log.Debugf("dynamodb: fim do validate")
	return claims, okClaims

}

// Async -
func (s *DynamoDB) Async() bool {
	return false
}

// Init -
func (s *DynamoDB) Init(ticker *time.Ticker) {

	//Nova Sessão com a AWS
	log.Debugf("dynamodb: Iniciando sessao com DynamoDB")

	log.Debugf("dynamodb: conectando na tabela %s, do dynamodb, na regiao %s ", s.tableName, s.region)
	ticker.Stop()

	// INFO nao se testa erro nesta funcao, deveria
	log.Debugf("dynamodb: criando uma sessao")
	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String(s.region)},
	)

	log.Debugf("dynamodb: criando um client Dynamo")
	// Cria um cliente DynamoDB
	s.svc = dynamodb.New(sess)
}
