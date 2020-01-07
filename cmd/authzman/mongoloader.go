package authzman

import (
	"context"
	"extauth/cmd/config"
	log "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"time"
)

type key string

type MongoCredential struct {
	ID          primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Fingerprint string             `json:"fingerprint,omitempty" bson:"fingerprint,omitempty"`
	Name        string             `json:"name,omitempty" bson:"name,omitempty"`
	Credentials []Credential       `json:"credentials,omitempty" bson:"credentials,omitempty"`
}

type MongoDB struct {
	uri      string
	database string
	client   *mongo.Client
}

func NewMongoStorage(config config.DBConf) *MongoDB {
	log.Debugf("criando objeto mongo com uri: %s e db: %s", config.Options["uri"], config.Options["database"])
	db := new(MongoDB)
	db.uri = config.Options["uri"]
	db.database = config.Options["database"]
	return db
}

// Carrega as permissoes de um bucket s3
func (s *MongoDB) LoadPermissions() (PermissionMap, bool) {
	return nil, false
}
func (s *MongoDB) Validate(pc PermissionClaim, appID string) (Credential, bool) {

	log.Debugf("mongodb: Validando fingerprint %s, path: %s", pc.Fingerprint, pc.Scope)
	okClaims := false
	var claims Credential
	credential := MongoCredential{}

	collection := s.client.Database(s.database).Collection("permission")
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	filter := bson.D{{"fingerprint", pc.Fingerprint}}
	err := collection.FindOne(ctx, filter).Decode(&credential)
	if err != nil {
		// ErrNoDocuments means that the filter did not match any documents in the collection
		if err == mongo.ErrNoDocuments {
			return claims, okClaims
		}
		log.Fatal(err)
	}

	log.Debugf("mongodb: [%d]credenciais encontradas para fingerprint %s", len(credential.Credentials), pc.Fingerprint)
	for idx := range credential.Credentials {
		log.Debugf("Testando fingerprint %s, Scope requisitado %s, scope encontrado %s", pc.Fingerprint, pc.Scope, credential.Credentials[idx].Scope)
		if credential.Credentials[idx].Scope == pc.Scope {
			log.Debugf("mongodb: credential %s", credential.Credentials[idx])
			okClaims = true
			claims = credential.Credentials[idx]
		}
	}
	log.Debugf("mongodb: CredentialEntry %s", credential)
	return claims, okClaims

}
func (s *MongoDB) Async() bool {
	return false
}

func (s *MongoDB) Init(ticker *time.Ticker) {
	log.Debugf("conectando em %s, uri:%s", s.uri, s.database)
	ticker.Stop()
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	clientOptions := options.Client().ApplyURI(s.uri)
	var err error
	s.client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatalf("nao foi possivel conectar no banco com o uri:%s", s.uri)
	}
}
