// GW de controle mTLS jwt
//
package main

import (
	c "extauth/cmd/config"
	"extauth/cmd/credential"
	"extauth/cmd/jwthandler"
	"fmt"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
)

// kill program
func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	//v1, err := defaultConf()
	var (
		err     error
		options c.Options
	)

	options, err = c.BuildOptions()
	//fmt.Print(options)
	if err != nil {
		panic(fmt.Errorf("Error when reading config: %v\n", err))
	}
	//
	// Configurando DEBUG
	switch options.Loglevel {
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)

	}
	// Iniciando o reconciliador de credenciais com o loader csv

	credentialMap := credential.New(options.Credentialdb.Loader)
	go credentialMap.Sched(options.Credentialdb.LoaderInterval, options.Credentialdb.Loader)

	//
	// Configurando o JWT Handler

	// Chave de assinatura dos tokens emitidos pelo GW
	privKeyPath := options.JwtConf.RsaPrivateFile
	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	// Issuer usado pelo GW
	localIssuer := options.JwtConf.LocalIssuer
	log.Debugf("local Issuer: %s", localIssuer)



	log.Debugf("authHeader: %s", options.AuthHeader)
	log.Debugf("claimString: %s", options.ClaimString)
	// Iniciando o gerenciador JWT
	myJwtHandler := jwthandler.New(signBytes, localIssuer, options.JwtConf.TokenLifetime,options.JwtConf.Kid )
	for i := 0; i < len(options.JwtConf.Issuers); i++ {
		err := myJwtHandler.AddJWK(options.JwtConf.Issuers[i].Issuer, options.JwtConf.Issuers[i].Url)
		if err != nil {
			log.Fatalf("Erro carregando JWTconf: %s iss: %s src: %s", err, options.JwtConf.Issuers[i].Issuer, options.JwtConf.Issuers[i].Url)
		}
	}

	//
	// Inicializando Servidor de Autorizacao
	// Injetando credentialCache de tokens, base de credenciais e gerenciador de JWT
	authServer := &AuthorizationServer{
		credentialCache: cache.New(options.Credentialdb.CacheInterval, options.Credentialdb.CacheClean),
		credentialMap:   credentialMap,
		jwtinstance:     myJwtHandler,
		//Oidc:            &options.Oidc,
		Options: &options,
	}

	// create a TCP listener on port 4000
	lis, err := net.Listen("tcp", ":4000")
	//fatal(err)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Infof("listening on %s ", lis.Addr()) //,authServer.jwtinstance.GetConf())

	grpcServer := grpc.NewServer()

	// Registrando o servidor de autenticacao no servidor GRPC
	auth.RegisterAuthorizationServer(grpcServer, authServer)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
