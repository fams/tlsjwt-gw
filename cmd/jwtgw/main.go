package main

import (
	"crypto/rsa"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/fams/jwt-go"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
	"os"
	"time"
)

const (
	privKeyPath           = "/auth/extauth.rsa" // openssl genrsa -out app.rsa keysize
	cache_expiration_time = 5
	cache_cleanup_time    = 10
	credentials_csv_file  = "/auth/auth.csv"
	//pubKeyPath  = "/auth/extauth.rsa.pub" // openssl rsa -in app.rsa -pubout > app.rsa.pub
)

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
	debug := os.Getenv("DEBUG")
	if len(debug) > 0 {
		log.SetLevel(log.DebugLevel)
	}

	//Carregando permissões iniciais
	//var initialLoader CredentialLoader = StaticLoader{}

	configMap.Init(CsvLoader{Cvspath: credentials_csv_file})

	//Carregando chaves de assinatura
	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	//Iniciando Cache
	//jwtcache = cache.New(cache_expiration_time*time.Minute, cache_cleanup_time*time.Minute)

	//Iniciando o reconciliador de credenciais com o loader csv
	var scheduleLoader CredentialLoader = CsvLoader{Cvspath: credentials_csv_file}

	go configMap.Sched(60, scheduleLoader)

	// create a TCP listener on port 4000
	lis, err := net.Listen("tcp", ":4000")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Infof("listening on %s", lis.Addr())

	grpcServer := grpc.NewServer()
	authServer := &AuthorizationServer{
		cache: cache.New(cache_expiration_time*time.Minute, cache_cleanup_time*time.Minute),
	}
	auth.RegisterAuthorizationServer(grpcServer, authServer)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}

}
