package authzman

import (
	"context"
	"extauth/cmd/config"
	"strconv"

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
	// Mostra a performance do tempo de busca no provedor de credenciais
	metricsTempoBuscaItemProvedor = promauto.NewSummaryVec(prometheus.SummaryOpts{
		Name: "gtw_summary_busca_provedor",
		Help: "Summary de conexao para buscar um item no provedor de credenciais",
		// Como serao exibidos os percentis
		Objectives: map[float64]float64{0.5: 0.05, 0.95: 0.005, 0.99: 0.001},
	},
		[]string{"id"},
	)
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
	timeout   int
	svc       *dynamodb.DynamoDB
}

// NewDynamoStorage -
func NewDynamoStorage(config config.DBConf) *DynamoDB {
	log.Debugf("dynamodb: criando objeto dynamodb com tablename: %s e region: %s", config.Options["tableName"], config.Options["region"])
	db := new(DynamoDB)
	db.tableName = config.Options["tableName"]
	db.region = config.Options["region"]
	db.timeout, _ = strconv.Atoi(config.Options["timeout"])

	log.Debugf("dynamodb: definido nome da tabela como: ", db.tableName)
	log.Debugf("dynamodb: definido regiao como: ", db.region)
	log.Debugf("dynamodb: definido tempo de timeout de busca: ", db.timeout)

	return db
}

// LoadPermissions - Carrega as permissoes de um bucket s3
func (s *DynamoDB) LoadPermissions() (PermissionMap, bool) {

	return nil, false
}

// Validate -
func (s *DynamoDB) Validate(pc PermissionClaim, appID string) (Credential, bool) {

	// INFO Nao esta imprimindo o pc.scope nos meus testes de dynamo
	log.Debugf("dynamodb: validando fingerprint %s, scope: %s", pc.Fingerprint, pc.Scope)
	okClaims := false
	var claims Credential

	log.Debugf("dynamodb: buscando item no dynamodb")

	// Inicia a contagem do tempo de busca dentro do provedor de credenciais
	start := time.Now()
	// Faz uma busca no DynamoDB a procura todos os scopes que aquele
	// fingerprint possui
	// Create a context with a timeout that will abort the GetItem if it takes
	// more than the passed in timeout.
	ctxItem, cancelFn := context.WithTimeout(context.Background(), time.Duration(s.timeout)*time.Second)

	// Certifica que o contexto sera finalizao no fim da execucao da aplicacao
	// caso essa situacao ocorra
	defer cancelFn()

	// Faz uma busca no DynamoDB a procura todos os scopes que aquele
	// fingerprint possui
	result, err := s.svc.GetItemWithContext(
		ctxItem,
		&dynamodb.GetItemInput{
			TableName: aws.String(s.tableName),
			Key: map[string]*dynamodb.AttributeValue{
				"fingerprint": {
					S: aws.String(pc.Fingerprint),
				},
			},
		},
	)

	// Faz o calculo de quantos milissegundos durou a busca
	elapsed := time.Now().Sub(start)

	// publica no prometheus
	metricsTempoBuscaItemProvedor.WithLabelValues(appID).Observe(float64(elapsed))

	// Verifica se a busca retornou erros
	if err != nil {
		log.Infof("dynamodb: falha buscar dados no dynamodb: %v", err)
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
		return claims, okClaims
	}

	log.Debugf("dynamodb: verificando se fingerprint eh vazio")

	if credential.Fingerprint == "" {
		log.Infof("dynamodb: fingerprint recuperado eh vazio. Nao encontrou-se a credencial no provedor remoto dynamodb")
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
		log.Infof("dynamodb: escopo recebido igual a '.', retornando falso")
		return claims, okClaims
	}

	log.Debugf("dynamodb: checando permissao de escopos")
	for idx := range credential.Credentials {
		log.Debugf("dynamodb: testando fingerprint %s, Scope requisitado %s, scope encontrado %s", pc.Fingerprint, pc.Scope, credential.Credentials[idx].Scope)
		if credential.Credentials[idx].Scope == escopoRequisicao {
			log.Debugf("dynamodb: credential %s", credential.Credentials[idx])
			okClaims = true
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
