package main

import (
	"crypto/rsa"
	"encoding/json"
	c "extauth/cmd/config"
	"fmt"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/fams/jwt-go"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
	"strconv"
	"time"
)

//const (
//	//privKeyPath           = "/auth/extauth.rsa" // openssl genrsa -out app.rsa keysize
//	//cache_expiration_time = 5
//	//cache_cleanup_time    = 10
//	//credentials_csv_file  = "/auth/auth.csv"
//	//pubKeyPath  = "/auth/extauth.rsa.pub" // openssl rsa -in app.rsa -pubout > app.rsa.pub
//)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

var (
	configMap = CredentialMap{} //Mapa com caminhos validos
	//verifyKey  *rsa.PublicKey //public key para auth
	signKey *rsa.PrivateKey //private key para assinar

)

func main() {
	// Definindo Padroes e lendo arquivo de configuracao
	v1, err := c.ReadConfig(".env",map[string]interface{}{
		"port":     8080,
		"hostname": "localhost",
		"debug": "info",
		"cache": map[string]interface{}{
			"expiration": 5,
			"cleanup": 10,
		},
		"credentials":map[string]string{
			"type": "csv",
			"config": "{\"path\": \"/auth/credential\"}",
			"reload": "60",
		},
		"jwt": map[string]string{
			"rsaPrivateFile": "/auth/extauth.rsa",
		},

	})
	if err != nil {
		panic(fmt.Errorf("Error when reading config: %v\n", err))
	}

	//
	// Configurando DEBUG
	switch v1.GetString("debug") {
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)

	}


	//
	// Configurando sincronizador de credenciais
	//
	var loader CredentialLoader
	credentialsConfig := v1.GetStringMapString("credentials")
//	sourceReloadInterval := source["reload"]
	interval,_ := strconv.Atoi(credentialsConfig["reload"])
//	interval,_ := strconv.Atoi(sourceReloadInterval)

	if(interval<10){
		log.Fatal("Intervalo de recarga de credenciais não pode ser < 10")
	}
	switch credentialsConfig["type"] {
		case "csv":
			var param map[string]interface{}
			if err := json.Unmarshal([]byte(credentialsConfig["config"]),&param); err != nil {
				log.Fatalf("Erro analisando config do provedor de credenciais", err)
			}
			loader = CsvLoader{param["path"].(string)}
	default:
		log.Fatal("Nenhum provedor de credenciais configurado")

	}

	//Carregando permissões iniciais
	configMap.Init(loader)

	//
	// Carregando chaves de assinatura

	jwtconf := v1.GetStringMapString("jwt")
	privKeyPath := jwtconf["rsaprivatefile"]

	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)



	//Configurar Cache
	cacheConf := v1.GetStringMap("cache")
	cleanup := cacheConf["cleanup"].(int)
	expiration := cacheConf["expiration"].(int)
	cacheCleanupTime := time.Duration(int64(cleanup))
	cacheExpirationTime := time.Duration(int64(expiration))

	//Iniciando o reconciliador de credenciais com o loader csv

	go configMap.Sched( time.Duration(interval), loader)



	// create a TCP listener on port 4000
	lis, err := net.Listen("tcp", ":4000")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Infof("listening on %s", lis.Addr())

	grpcServer := grpc.NewServer()
	authServer := &AuthorizationServer{
		cache: cache.New( cacheCleanupTime* time.Minute, cacheExpirationTime*time.Minute),
	}
	auth.RegisterAuthorizationServer(grpcServer, authServer)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
