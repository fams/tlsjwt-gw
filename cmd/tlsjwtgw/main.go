package main

import (
	c "extauth/cmd/config"
	"extauth/cmd/credential"
	"extauth/cmd/jwthandler"
	"fmt"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	"github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
	"time"
)

// kill program
func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type credentialConf struct {
	loader         credential.CredentialLoader
	loaderInterval time.Duration
	cacheInterval  time.Duration
	cacheClean     time.Duration
}
type issuerConf ***REMOVED***face {
	iss() string
	jwks() jwthandler.Jwks
}

type jwtConf struct {
	rsaPrivateFile string
	localIssuer    string
	Issuers        *[]issuerConf
}

type gwOptions struct {
	loglevel     string
	port         int
	hostname     string
	oidc         oidcConf
	credentialdb *credentialConf
	jwtConf      *jwtConf
}

// Default conf
func defaultConf() (v1 *viper.Viper, err error) {
	// Definindo Padroes e lendo arquivo de configuracao
	v1, err = c.ReadConfig("extauth", map[string]***REMOVED***face{}{
		"port":     8080,
		"hostname": "localhost",
		"loglevel": "debug",
		"oidc": map[string]***REMOVED***face{}{
			"hostname": "localhost",
			"path":     "/auth",
		},

		"credentialCache": map[string]***REMOVED***face{}{
			"expiration": 31,
			"cleanup":    60,
		},
		"credentials": map[string]string{
			"type":   "csv",
			"config": "{\"path\": \"/auth/credential\"}",
			"path":   "/auth/credential",
			"reload": "60",
		},
		"jwt": map[string]***REMOVED***face{}{
			"rsaPrivateFile": "/auth/extauth.rsa",
			"localIssuer":    "tlsgw.local",
			"issuers": map[string]***REMOVED***face{}{
				"name1": map[string]***REMOVED***face{}{
					"iss": "tlsgw.local",
					"local": map[string]string{
						"rsaPublicFile": "/auth/extauth.rsa.pub",
					},
				},
				"name2": map[string]***REMOVED***face{}{
					"iss": "oauth.tlsgw.local",
					"remote": map[string]string{
						"url": "oauth.backend.local/uat/.well-known/jwks.json",
					},
				},
			},
		},
	})
	return
}

func buildOptions() (gwOptions, error) {
	v1, err := defaultConf()
	if err != nil {
		panic(fmt.Errorf("Error when reading config: %v\n", err))
	}
	var opt gwOptions
	opt.hostname = v1.GetString("hostname")
	opt.port = v1.GetInt("port")

	opt.loglevel = v1.GetString("loglevel")
	//
	// Credentials
	//var cc credentialConf
	credentialdb := &credentialConf{}
	opt.credentialdb = credentialdb

	***REMOVED***val := v1.GetInt("credentials.reload")
	if ***REMOVED***val < 10 {
		log.Fatal("Intervalo de recarga de credenciais não pode ser < 10")
	}

	opt.credentialdb.loaderInterval = time.Duration(***REMOVED***val)

	switch v1.GetString("credentials.type") {
	case "csv":
		//path := v1.GetString("credentials.path")
		//var param map[string]***REMOVED***face{}
		if path := v1.GetString("credentials.path"); len(path) < 2 {
			log.Fatalf("Erro analisando config do provedor de credenciais %v", err)
		} else {
			opt.credentialdb.loader = &credential.CsvLoader{CsvPath: path}
		}
	case "s3":
		bucket := v1.GetString("credentials.bucket")
		key := v1.GetString("credentials.key")
		region := v1.GetString("credentials.region")
		opt.credentialdb.loader = &credential.S3loader{BucketName: bucket, KeyName: key, Region: region}
	default:
		log.Fatal("Nenhum provedor de credenciais configurado")
	}

	opt.credentialdb.cacheClean = time.Duration(v1.GetInt64("credentialCache.cleanup")) * time.Minute
	opt.credentialdb.cacheInterval = time.Duration(v1.GetInt64("credentialCache.expiration")) * time.Minute
	if opt.credentialdb.cacheInterval > opt.credentialdb.cacheClean || opt.credentialdb.cacheInterval < 30 {
		log.Fatal("Tempo de vida do cache minimo 30s, tempo de limpeza deve ser superior ao tempo de vida")
	}
	var jwtConf jwtConf
	opt.jwtConf = &jwtConf
	// Chave de assinatura dos tokens emitidos pelo GW
	opt.jwtConf.rsaPrivateFile = v1.GetString("jwt.rsaprivatefile")
	opt.jwtConf.localIssuer = v1.GetString("jwt.localIssuer")

	issuers := v1.GetStringMap("jwt.issuers")
	for k := range issuers {
		iss := v1.GetString(fmt.Sprintf("jwt.issuers.%s.iss", k))

		if local := v1.GetStringMapString(fmt.Sprintf("jwt.issuers.%s.local", k)); len(local) > 0 {
			jwksFile := local["rsaPublicFile"]
			log.Debugf("Issuer: %s\njwksFile: %s\n", iss, jwksFile)
		}
		if remote := v1.GetStringMapString(fmt.Sprintf("jwt.issuers.%s.remote", k)); len(remote) > 0 {
			url := remote["url"]
			log.Debugf("Issuer: %s\nurl: %s\n", iss, url)
		}
	}

	opt.oidc = oidcConf{v1.GetString("oidc.hostname"), v1.GetString("oidc.path")}

	fatal(err)

	// Issuer usado pelo GW
	localIssuer := v1.GetString("jwt.localissuer")
	log.Debugf("Local Issuer: %s", localIssuer)

	return opt, err
}
func main() {
	//v1, err := defaultConf()
	var (
		err     error
		options gwOptions
	)

	options, err = buildOptions()
	//fmt.Print(options)
	if err != nil {
		panic(fmt.Errorf("Error when reading config: %v\n", err))
	}
	//
	// Configurando DEBUG
	switch options.loglevel {
	case "info":
		log.SetLevel(log.InfoLevel)
	case "debug":
		log.SetLevel(log.DebugLevel)
	default:
		log.SetLevel(log.InfoLevel)

	}
	// Iniciando o reconciliador de credenciais com o loader csv

	credentialMap := credential.New(options.credentialdb.loader)
	go credentialMap.Sched(options.credentialdb.loaderInterval, options.credentialdb.loader)

	//
	// Configurando o JWT Handler

	// Chave de assinatura dos tokens emitidos pelo GW
	privKeyPath := options.jwtConf.rsaPrivateFile
	signBytes, err := ioutil.ReadFile(privKeyPath)
	fatal(err)

	// Issuer usado pelo GW
	localIssuer := options.jwtConf.localIssuer
	log.Debugf("Local Issuer: %s", localIssuer)

	// Iniciando o gerenciador JWT
	myJwtHandler := jwthandler.New(signBytes, localIssuer)

	//
	// Inicializando Servidor de Autorizacao
	// Injetando credentialCache de tokens, base de credenciais e gerenciador de JWT
	authServer := &AuthorizationServer{
		credentialCache: cache.New(options.credentialdb.cacheInterval, options.credentialdb.cacheClean),
		credentialMap:   credentialMap,
		jwtinstance:     myJwtHandler,
		oidc:            &options.oidc,
	}

	// create a TCP listener on port 4000
	lis, err := net.Listen("tcp", ":4000")
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
