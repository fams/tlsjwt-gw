// GW de controle mTLS jwt
//
package main

import (
	"extauth/cmd/authzman"
	c "extauth/cmd/config"
	"extauth/cmd/jwthandler"
	"fmt"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
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

	// Iniciando o reconciliador de credenciais com o loader
	//var PermissionManager authzman.AuthzDB
	PermissionManager := authzman.NewPermDb(options.PermissionDB.Config)

	if PermissionManager.Async() {
		duration, err := time.ParseDuration(options.PermissionDB.Config.Options["interval"])
		if err == nil {
			tick := time.NewTicker(duration)
			go PermissionManager.Init(tick)
		}else{
			log.Debugf("Não foi possivel converter %s para time.duration ",options.PermissionDB.Config.Options["interval"] )
			fatal(err)
		}
	}else{
		log.Info("iniciando banco syncrono")
		ticker := time.NewTicker(time.Second)
		PermissionManager.Init(ticker)
	}
	//
	// Configurando o JWT Handler
	//

	// Chave de assinatura dos tokens emitidos pelo GW
	privKeyPath := options.JwtConf.RsaPrivateFile
	signKeyBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	// Issuer usado pelo GW
	localIssuer := options.JwtConf.LocalIssuer
	log.Debugf("local Issuer: %s", localIssuer)
	log.Debugf("authzHeader: %s", options.AuthHeader)
	log.Debugf("claimString: %s", options.ClaimString)

	// Iniciando o gerenciador JWT
	myJwtHandler := jwthandler.New(signKeyBytes, localIssuer, options.JwtConf.TokenLifetime, options.JwtConf.Kid )
	for i := 0; i < len(options.JwtConf.Issuers); i++ {
		err := myJwtHandler.AddJWK(options.JwtConf.Issuers[i].Issuer, options.JwtConf.Issuers[i].Url)
		if err != nil {
			log.Fatalf("Erro carregando JWTconf: %s iss: %s src: %s", err, options.JwtConf.Issuers[i].Issuer, options.JwtConf.Issuers[i].Url)
		}
	}

	//
	// Inicializando Servidor de Autorizacao
	// Injetando Cache de tokens, base de credenciais e gerenciador de JWT
	authServer := &AuthorizationServer{
		credentialCache:   cache.New(options.PermissionDB.CacheInterval, options.PermissionDB.CacheClean),
		PermissionManager: PermissionManager,
		jwtinstance:       myJwtHandler,
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

	// Graceful end
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
	grpcServer.Stop()

}
